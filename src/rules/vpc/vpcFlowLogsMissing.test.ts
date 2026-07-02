import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { vpcFlowLogsMissing } from './vpcFlowLogsMissing';

describe('vpc-flow-logs-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [vpcFlowLogsMissing]);

  it('flags a VPC with no flow log', () => {
    expect(
      run({
        Resources: {
          Vpc: {
            Type: 'AWS::EC2::VPC',
            Properties: { CidrBlock: '10.0.0.0/16' },
          },
        },
      })
    ).toHaveLength(1);
  });

  it('does not flag a VPC targeted by a flow log via Ref', () => {
    expect(
      run({
        Resources: {
          Vpc: {
            Type: 'AWS::EC2::VPC',
            Properties: { CidrBlock: '10.0.0.0/16' },
          },
          FlowLog: {
            Type: 'AWS::EC2::FlowLog',
            Properties: { ResourceType: 'VPC', ResourceId: { Ref: 'Vpc' } },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('still flags when the flow log targets a different VPC', () => {
    const findings = run({
      Resources: {
        Vpc: {
          Type: 'AWS::EC2::VPC',
          Properties: { CidrBlock: '10.0.0.0/16' },
        },
        Other: {
          Type: 'AWS::EC2::VPC',
          Properties: { CidrBlock: '10.1.0.0/16' },
        },
        FlowLog: {
          Type: 'AWS::EC2::FlowLog',
          Properties: { ResourceType: 'VPC', ResourceId: { Ref: 'Other' } },
        },
      },
    });
    expect(findings.map((finding) => finding.resourceId)).toEqual(['Vpc']);
  });
});
