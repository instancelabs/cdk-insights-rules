import type { Rule } from '../../types';

const hasSourceRestriction = (
  props: Record<string, unknown> | undefined
): boolean =>
  Boolean(
    props && (props.SourceArn || props.SourceAccount || props.PrincipalOrgID)
  );

const isServicePrincipal = (principal: unknown): boolean =>
  typeof principal === 'string' && principal.endsWith('.amazonaws.com');

/**
 * lambda-permission-service-unrestricted — the confused-deputy companion to
 * lambda-permission-public.
 *
 * A Lambda permission granting a *service* principal (s3.amazonaws.com,
 * sns.amazonaws.com, ...) without SourceArn / SourceAccount / PrincipalOrgID
 * lets that service invoke the function on behalf of ANY account — an
 * attacker points their own bucket/topic at your function.
 */
export const lambdaPermissionServiceUnrestricted: Rule = {
  metadata: {
    ruleId: 'lambda-permission-service-unrestricted',
    name: 'Lambda Permission Service Principal Unrestricted',
    description:
      'Detects Lambda permissions that grant an AWS service principal invoke rights without a SourceArn/SourceAccount restriction (confused-deputy risk).',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Lambda::Permission'],
    awsDocUrl:
      'https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html',
    remediationSteps: [
      'Set SourceArn to the specific resource that may invoke the function',
      'Or set SourceAccount to your AWS account ID',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::Lambda::Permission') {
        continue;
      }
      const props = resource.Properties;
      if (
        isServicePrincipal(props?.Principal) &&
        !hasSourceRestriction(props)
      ) {
        report(resourceId, {
          issue: `Lambda permission grants ${props?.Principal} invoke rights without a SourceArn/SourceAccount restriction.`,
          recommendation:
            'Add SourceArn (the specific bucket/topic/rule allowed to invoke) or SourceAccount — without one, the service will invoke your function on behalf of any AWS account (confused deputy).',
        });
      }
    }
  },

  example: {
    flagged: `import * as lambda from 'aws-cdk-lib/aws-lambda';

new lambda.CfnPermission(this, 'Permission', {
  action: 'lambda:InvokeFunction',
  functionName: 'my-function',
  principal: 's3.amazonaws.com',
});`,
    fixed: `import * as lambda from 'aws-cdk-lib/aws-lambda';

new lambda.CfnPermission(this, 'Permission', {
  action: 'lambda:InvokeFunction',
  functionName: 'my-function',
  principal: 's3.amazonaws.com',
  sourceAccount: '111122223333',
  sourceArn: 'arn:aws:s3:::my-bucket',
});`,
  },
};
