import type { CfnTemplate, Rule } from '../../types';

const collectReferencedIds = (value: unknown, out: Set<string>): void => {
  if (Array.isArray(value)) {
    for (const item of value) {
      collectReferencedIds(item, out);
    }
  } else if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    if (typeof obj.Ref === 'string') {
      out.add(obj.Ref);
    }
    const getAtt = obj['Fn::GetAtt'];
    if (Array.isArray(getAtt) && typeof getAtt[0] === 'string') {
      out.add(getAtt[0]);
    } else if (typeof getAtt === 'string') {
      out.add(getAtt.split('.')[0]);
    }
    for (const value of Object.values(obj)) {
      collectReferencedIds(value, out);
    }
  }
};

/** Table logical ids with an Application Auto Scaling target attached. */
const autoScaledTables = (template: CfnTemplate): Set<string> => {
  const scaled = new Set<string>();
  for (const resource of Object.values(template.Resources ?? {})) {
    if (resource.Type !== 'AWS::ApplicationAutoScaling::ScalableTarget') {
      continue;
    }
    const dimension = resource.Properties?.ScalableDimension;
    if (
      typeof dimension !== 'string' ||
      !dimension.startsWith('dynamodb:table:')
    ) {
      continue;
    }
    collectReferencedIds(resource.Properties?.ResourceId, scaled);
  }
  return scaled;
};

/**
 * dynamodb-autoscaling-missing
 *
 * A provisioned-capacity table with no Application Auto Scaling target pays
 * for peak capacity around the clock (or throttles at peak). On-demand
 * tables are exempt.
 */
export const dynamodbAutoscalingMissing: Rule = {
  metadata: {
    ruleId: 'dynamodb-autoscaling-missing',
    name: 'DynamoDB Auto Scaling Missing',
    description:
      'Detects provisioned-capacity DynamoDB tables without Application Auto Scaling.',
    severity: 'MEDIUM',
    wafPillar: 'Cost Optimization',
    resourceTypes: ['AWS::DynamoDB::Table'],
    awsDocUrl:
      'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/AutoScaling.html',
    remediationSteps: [
      'Attach ApplicationAutoScaling ScalableTargets for read/write capacity, or switch BillingMode to PAY_PER_REQUEST',
    ],
  },

  check: (template, report) => {
    const scaled = autoScaledTables(template);
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::DynamoDB::Table') {
        continue;
      }
      const billingMode = resource.Properties?.BillingMode;
      if (billingMode === 'PAY_PER_REQUEST') {
        continue;
      }
      if (!resource.Properties?.ProvisionedThroughput) {
        continue; // no decidable provisioned capacity
      }
      if (!scaled.has(resourceId)) {
        report(resourceId, {
          issue:
            'Provisioned-capacity DynamoDB table has no auto scaling configured.',
          recommendation:
            'Add Application Auto Scaling targets for read/write capacity, or use PAY_PER_REQUEST billing so capacity follows traffic.',
        });
      }
    }
  },

  example: {
    flagged: `import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

new dynamodb.CfnTable(this, 'Table', {
  keySchema: [{ attributeName: 'id', keyType: 'HASH' }],
  attributeDefinitions: [{ attributeName: 'id', attributeType: 'S' }],
  provisionedThroughput: { readCapacityUnits: 50, writeCapacityUnits: 50 },
});`,
    fixed: `import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

new dynamodb.CfnTable(this, 'Table', {
  keySchema: [{ attributeName: 'id', keyType: 'HASH' }],
  attributeDefinitions: [{ attributeName: 'id', attributeType: 'S' }],
  billingMode: 'PAY_PER_REQUEST',
});`,
  },
};
