import type { Rule } from '../../types';

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
 * lambda-permission-scoped-wildcard — the advisory companion to
 * lambda-permission-public.
 *
 * A wildcard Principal that IS scoped by SourceArn / SourceAccount /
 * PrincipalOrgID is broad but not public. Naming the specific account ids
 * is still preferable — the restriction is one condition-edit away from
 * public. LayerVersionPermissions scoped by OrganizationId are the
 * documented org-sharing pattern and are exempt.
 */
export const lambdaPermissionScopedWildcard: Rule = {
  metadata: {
    ruleId: 'lambda-permission-scoped-wildcard',
    name: 'Lambda Permission Scoped Wildcard Principal',
    description:
      'Detects Lambda permissions using a wildcard Principal scoped only by a source/org condition.',
    severity: 'LOW',
    wafPillar: 'Security',
    resourceTypes: [
      'AWS::Lambda::Permission',
      'AWS::Lambda::LayerVersionPermission',
    ],
    awsDocUrl:
      'https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html',
    remediationSteps: [
      'Prefer naming specific AWS account IDs over Principal "*" with a scoping condition',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      const isPermission = resource.Type === 'AWS::Lambda::Permission';
      const isLayerPermission =
        resource.Type === 'AWS::Lambda::LayerVersionPermission';
      if (!isPermission && !isLayerPermission) {
        continue;
      }
      const props = resource.Properties;
      if (props?.Principal !== '*' || !hasSourceRestriction(props)) {
        continue;
      }
      // Org-shared layers are the documented pattern for OrganizationId.
      if (isLayerPermission && props?.OrganizationId) {
        continue;
      }
      report(resourceId, {
        issue: `${resource.Type} uses a wildcard Principal scoped only by a source/org restriction — broad but not public.`,
        recommendation:
          'Prefer specific AWS account IDs over Principal "*" — the scoping condition is a single edit away from making the grant public.',
      });
    }
  },

  example: {
    flagged: `import * as lambda from 'aws-cdk-lib/aws-lambda';

new lambda.CfnPermission(this, 'Permission', {
  action: 'lambda:InvokeFunction',
  functionName: 'my-function',
  principal: '*',
  principalOrgId: 'o-abc123',
});`,
    fixed: `import * as lambda from 'aws-cdk-lib/aws-lambda';

new lambda.CfnPermission(this, 'Permission', {
  action: 'lambda:InvokeFunction',
  functionName: 'my-function',
  principal: '111122223333',
});`,
  },
};
