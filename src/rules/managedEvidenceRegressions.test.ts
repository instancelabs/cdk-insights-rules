import { describe, expect, it } from 'vitest';
import { runRules } from '../runRules';
import { securityGroupUnrestrictedEgress } from './ec2/securityGroupUnrestrictedEgress';
import { securityGroupUnrestrictedIngress } from './ec2/securityGroupUnrestrictedIngress';
import { lambdaDlqMissing } from './lambda/lambdaDlqMissing';
import { s3BucketAccessLoggingDisabled } from './s3/s3BucketAccessLoggingDisabled';
import { s3BucketEncryptionAwsManaged } from './s3/s3BucketEncryptionAwsManaged';
import { s3LifecyclePolicyMissing } from './s3/s3LifecyclePolicyMissing';

describe('managed scan evidence regressions', () => {
  it.each(['0.0.0.0/0', '::/0'])(
    'does not flag individual HTTP/HTTPS rules as dangerous ingress: %s',
    (cidr) => {
      const source = cidr.includes(':') ? { CidrIpv6: cidr } : { CidrIp: cidr };
      const resources = Object.fromEntries(
        [80, 443, 22].map((port) => [
          `Port${port}`,
          {
            Type: 'AWS::EC2::SecurityGroupIngress',
            Properties: {
              ...source,
              IpProtocol: 'tcp',
              FromPort: port,
              ToPort: port,
            },
          },
        ])
      );
      const findings = runRules({ Resources: resources }, [
        securityGroupUnrestrictedIngress,
      ]);
      expect(findings.map((f) => f.resourceId)).toEqual(['Port22']);
      expect(findings[0].severity).toBe('HIGH');
      expect(findings[0].issue).toContain('depends on routing');
    }
  );
  it('preserves a range of exposed ports even if its endpoints are web ports', () => {
    expect(
      runRules(
        {
          Resources: {
            Sg: {
              Type: 'AWS::EC2::SecurityGroupIngress',
              Properties: {
                IpProtocol: 'tcp',
                FromPort: 80,
                ToPort: 443,
                CidrIp: '0.0.0.0/0',
              },
            },
          },
        },
        [securityGroupUnrestrictedIngress]
      )
    ).toHaveLength(1);
  });
  it('describes HTTPS-only egress without claiming all ports are open', () => {
    const [finding] = runRules(
      {
        Resources: {
          Sg: {
            Type: 'AWS::EC2::SecurityGroup',
            Properties: {
              SecurityGroupEgress: [
                {
                  IpProtocol: 'tcp',
                  FromPort: 443,
                  ToPort: 443,
                  CidrIpv6: '::/0',
                },
              ],
            },
          },
        },
      },
      [securityGroupUnrestrictedEgress]
    );
    expect(finding.issue).toContain('configured protocols and ports');
  });
  it('keeps optional S3 choices at advisory severity with workload requirements', () => {
    const findings = runRules(
      { Resources: { Bucket: { Type: 'AWS::S3::Bucket' } } },
      [
        s3BucketEncryptionAwsManaged,
        s3BucketAccessLoggingDisabled,
        s3LifecyclePolicyMissing,
      ]
    );
    expect(findings).toHaveLength(3);
    expect(findings.every((f) => f.severity === 'LOW')).toBe(true);
    expect(findings[2].recommendation).toContain(
      'Do not introduce an arbitrary deletion period'
    );
  });
  const mapping = (source: unknown, destination?: unknown) => ({
    Type: 'AWS::Lambda::EventSourceMapping',
    Properties: {
      FunctionName: { Ref: 'Fn' },
      EventSourceArn: source,
      DestinationConfig: destination,
    },
  });
  it('leaves SQS recovery to queue rules and does not invent a mapping destination', () => {
    const findings = runRules(
      {
        Resources: {
          Fn: { Type: 'AWS::Lambda::Function' },
          Queue: { Type: 'AWS::SQS::Queue' },
          Mapping: mapping({ 'Fn::GetAtt': ['Queue', 'Arn'] }),
        },
      },
      [lambdaDlqMissing]
    );
    expect(findings).toHaveLength(0);
  });
  it('recognizes an existing stream mapping failure destination', () => {
    expect(
      runRules(
        {
          Resources: {
            Fn: { Type: 'AWS::Lambda::Function' },
            Stream: { Type: 'AWS::Kinesis::Stream' },
            Mapping: mapping(
              { 'Fn::GetAtt': ['Stream', 'Arn'] },
              {
                OnFailure: {
                  Destination: 'arn:aws:sqs:eu-west-2:111122223333:failed',
                },
              }
            ),
          },
        },
        [lambdaDlqMissing]
      )
    ).toHaveLength(0);
  });
  it('retains a stream failure warning despite a function-level DLQ', () => {
    expect(
      runRules(
        {
          Resources: {
            Fn: {
              Type: 'AWS::Lambda::Function',
              Properties: {
                DeadLetterConfig: {
                  TargetArn: 'arn:aws:sqs:eu-west-2:111122223333:failed',
                },
              },
            },
            Stream: { Type: 'AWS::Kinesis::Stream' },
            Mapping: mapping({ 'Fn::GetAtt': ['Stream', 'Arn'] }),
          },
        },
        [lambdaDlqMissing]
      )
    ).toHaveLength(1);
  });
  it('retains independent async recovery requirements for a function also using SQS', () => {
    expect(
      runRules(
        {
          Resources: {
            Fn: { Type: 'AWS::Lambda::Function' },
            Mapping: mapping('arn:aws:sqs:eu-west-2:111122223333:q'),
            Permission: {
              Type: 'AWS::Lambda::Permission',
              Properties: {
                FunctionName: { Ref: 'Fn' },
                Principal: 'sns.amazonaws.com',
              },
            },
          },
        },
        [lambdaDlqMissing]
      )
    ).toHaveLength(1);
  });
});
