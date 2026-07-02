import { asStatements, isWildcardPrincipal } from '../../policy.js';
import type { PolicyStatement } from '../../policy.js';
import type { Rule } from '../../types';

const hasMeaningfulCondition = (condition: unknown): boolean =>
  !!condition &&
  typeof condition === 'object' &&
  Object.keys(condition as Record<string, unknown>).length > 0;

const isUnrestrictedAllow = (statement: PolicyStatement): boolean =>
  statement.Effect === 'Allow' &&
  isWildcardPrincipal(statement.Principal) &&
  !hasMeaningfulCondition(statement.Condition);

/**
 * eventbridge-bus-policy-wildcard-principal
 *
 * An event bus policy that Allows `Principal: '*'` with no Condition lets any
 * AWS account put events onto your bus — a straight injection channel into
 * everything the bus triggers. Handles both the legacy top-level
 * Principal/Condition properties and the Statement form (object or JSON
 * string). A wildcard scoped by any Condition (e.g. aws:PrincipalOrgID) is
 * broad but not public, and is not flagged.
 */
export const eventbridgeBusPolicyWildcardPrincipal: Rule = {
  metadata: {
    ruleId: 'eventbridge-bus-policy-wildcard-principal',
    name: 'EventBridge Bus Policy Wildcard Principal',
    description:
      'Detects event bus policies that allow a wildcard principal without any condition, letting any AWS account put events onto the bus.',
    severity: 'CRITICAL',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Events::EventBusPolicy'],
    awsDocUrl:
      'https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-bus-perms.html',
    remediationSteps: [
      'Set Principal to a specific AWS account ID',
      'Or keep the wildcard but add a Condition scoping it (e.g. aws:PrincipalOrgID for your organization)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::Events::EventBusPolicy') {
        continue;
      }
      const props = resource.Properties ?? {};

      // Legacy shape: Principal / Condition as top-level properties.
      const legacyStatement: PolicyStatement | undefined =
        props.Principal !== undefined
          ? {
              Effect: 'Allow',
              Principal: props.Principal,
              Condition: props.Condition,
            }
          : undefined;

      // Statement shape: a single statement object (or JSON string), or a
      // document with a Statement list.
      let statementValue: unknown = props.Statement;
      if (typeof statementValue === 'string') {
        try {
          statementValue = JSON.parse(statementValue);
        } catch {
          statementValue = undefined;
        }
      }
      const statements: PolicyStatement[] = [
        ...(legacyStatement ? [legacyStatement] : []),
        ...asStatements({ Statement: statementValue }),
      ];

      if (statements.some(isUnrestrictedAllow)) {
        report(resourceId, {
          issue:
            'Event bus policy allows a wildcard principal with no condition — any AWS account can put events onto this bus.',
          recommendation:
            'Restrict the policy to specific account IDs, or scope the wildcard with a Condition such as aws:PrincipalOrgID.',
        });
      }
    }
  },

  example: {
    flagged: `import * as events from 'aws-cdk-lib/aws-events';

new events.CfnEventBusPolicy(this, 'BusPolicy', {
  statementId: 'AllowPutEvents',
  action: 'events:PutEvents',
  principal: '*',
});`,
    fixed: `import * as events from 'aws-cdk-lib/aws-events';

new events.CfnEventBusPolicy(this, 'BusPolicy', {
  statementId: 'AllowPutEvents',
  action: 'events:PutEvents',
  principal: '111122223333',
});`,
  },
};
