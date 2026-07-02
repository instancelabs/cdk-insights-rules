import type { Rule } from '../../types';

/** SourceArn/SourceAccount/PrincipalOrgID/OrganizationId scope a grant. */
const hasSourceRestriction = (
  props: Record<string, unknown> | undefined
): boolean =>
  Boolean(
    props &&
      (props.SourceArn ||
        props.SourceAccount ||
        props.PrincipalOrgID ||
        props.OrganizationId)
  );

/**
 * lambda-permission-public
 *
 * An AWS::Lambda::Permission (or LayerVersionPermission) with a wildcard
 * Principal and no SourceArn / SourceAccount / PrincipalOrgID restriction lets
 * ANY AWS account invoke the function or use the layer. This rule flags only
 * that truly-public shape; a wildcard scoped by a source restriction, or an
 * unrestricted *service* principal (confused-deputy risk), are lesser,
 * separate concerns.
 */
export const lambdaPermissionPublic: Rule = {
  metadata: {
    ruleId: 'lambda-permission-public',
    name: 'Lambda Permission Grants Public Access',
    description:
      'Detects Lambda permissions and layer-version permissions with a wildcard Principal and no source restriction, letting any AWS account invoke the function or use the layer.',
    severity: 'CRITICAL',
    wafPillar: 'Security',
    resourceTypes: [
      'AWS::Lambda::Permission',
      'AWS::Lambda::LayerVersionPermission',
    ],
    awsDocUrl:
      'https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html',
    remediationSteps: [
      'Replace the wildcard Principal with a specific 12-digit AWS account ID',
      'For service principals, set SourceArn to the specific resource that may invoke the function (or SourceAccount to your account ID)',
      'For LayerVersionPermission, prefer OrganizationId over a wildcard Principal',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type !== 'AWS::Lambda::Permission' &&
        resource.Type !== 'AWS::Lambda::LayerVersionPermission'
      ) {
        continue;
      }
      const props = resource.Properties;
      const principal = props?.Principal;
      const isWildcard = principal === '*' || principal === undefined;
      if (isWildcard && !hasSourceRestriction(props)) {
        report(resourceId, {
          issue: `${resource.Type} grants public access via a wildcard Principal with no source restriction.`,
          recommendation:
            'Set Principal to a specific AWS account ID, or keep a service principal but add SourceArn/SourceAccount/PrincipalOrgID — a wildcard principal makes the function or layer reachable from any AWS account.',
        });
      }
    }
  },

  example: {
    flagged: `import * as lambda from 'aws-cdk-lib/aws-lambda';

new lambda.CfnPermission(this, 'Permission', {
  action: 'lambda:InvokeFunction',
  functionName: 'my-function',
  principal: '*',
});`,
    fixed: `import * as lambda from 'aws-cdk-lib/aws-lambda';

new lambda.CfnPermission(this, 'Permission', {
  action: 'lambda:InvokeFunction',
  functionName: 'my-function',
  principal: '111122223333',
});`,
  },
};
