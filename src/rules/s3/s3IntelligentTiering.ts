import type { Rule } from '../../types';

const toArray = (value: unknown): unknown[] => {
  if (value === undefined || value === null) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
};

const hasIntelligentTieringTransition = (properties: unknown): boolean => {
  const props = properties as
    | { LifecycleConfiguration?: { Rules?: unknown } }
    | undefined;
  const rules = toArray(props?.LifecycleConfiguration?.Rules);
  return rules.some((rule) => {
    const entry = rule as Record<string, unknown>;
    const transitions = [
      ...toArray(entry.Transitions),
      ...toArray(entry.NoncurrentVersionTransitions),
      ...toArray(entry.NoncurrentVersionTransition),
    ];
    return transitions.some(
      (transition) =>
        (transition as { StorageClass?: string })?.StorageClass ===
        'INTELLIGENT_TIERING'
    );
  });
};

/**
 * s3-intelligent-tiering
 *
 * Advisory: Intelligent-Tiering moves objects between access tiers
 * automatically — the low-effort cost win for buckets with unknown access
 * patterns. Buckets with an IntelligentTieringConfiguration or an
 * INTELLIGENT_TIERING lifecycle transition are covered.
 */
export const s3IntelligentTiering: Rule = {
  metadata: {
    ruleId: 's3-intelligent-tiering',
    name: 'S3 Intelligent-Tiering Not Used',
    description:
      'Detects S3 buckets not using Intelligent-Tiering for automatic cost optimization.',
    severity: 'LOW',
    wafPillar: 'Cost Optimization',
    resourceTypes: ['AWS::S3::Bucket'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonS3/latest/userguide/intelligent-tiering.html',
    remediationSteps: [
      'Add a lifecycle transition to INTELLIGENT_TIERING (or an IntelligentTieringConfiguration) for buckets with unpredictable access patterns',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::S3::Bucket') {
        continue;
      }
      const configs = resource.Properties?.IntelligentTieringConfigurations;
      const hasConfig = Array.isArray(configs) && configs.length > 0;
      if (!hasConfig && !hasIntelligentTieringTransition(resource.Properties)) {
        report(resourceId, {
          issue: 'S3 bucket does not use Intelligent-Tiering.',
          recommendation:
            'For buckets with unpredictable access patterns, transition objects to INTELLIGENT_TIERING so AWS moves cold data to cheaper tiers automatically.',
        });
      }
    }
  },

  example: {
    flagged: `import * as s3 from 'aws-cdk-lib/aws-s3';

new s3.CfnBucket(this, 'Bucket', {});`,
    fixed: `import * as s3 from 'aws-cdk-lib/aws-s3';

new s3.CfnBucket(this, 'Bucket', {
  lifecycleConfiguration: {
    rules: [
      {
        id: 'tiering',
        status: 'Enabled',
        transitions: [
          { storageClass: 'INTELLIGENT_TIERING', transitionInDays: 0 },
        ],
      },
    ],
  },
});`,
  },
};
