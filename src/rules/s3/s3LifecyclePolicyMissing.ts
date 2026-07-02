import type { Rule } from '../../types';

/**
 * s3-lifecycle-policy-missing
 *
 * A bucket with no lifecycle rules never transitions or expires anything —
 * storage (and noncurrent versions, on versioned buckets) grows forever.
 */
export const s3LifecyclePolicyMissing: Rule = {
  metadata: {
    ruleId: 's3-lifecycle-policy-missing',
    name: 'S3 Lifecycle Policy Missing',
    description: 'Detects S3 buckets without lifecycle rules.',
    severity: 'MEDIUM',
    wafPillar: 'Cost Optimization',
    resourceTypes: ['AWS::S3::Bucket'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html',
    remediationSteps: [
      'Add LifecycleConfiguration rules transitioning cold objects and expiring noncurrent versions',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::S3::Bucket') {
        continue;
      }
      const rules = resource.Properties?.LifecycleConfiguration?.Rules;
      if (!Array.isArray(rules) || rules.length === 0) {
        report(resourceId, {
          issue: 'S3 bucket has no lifecycle policy configured.',
          recommendation:
            'Add lifecycle rules to transition cold data to cheaper storage classes and expire noncurrent versions.',
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
        id: 'archive',
        status: 'Enabled',
        transitions: [{ storageClass: 'GLACIER', transitionInDays: 90 }],
        noncurrentVersionExpiration: { noncurrentDays: 30 },
      },
    ],
  },
});`,
  },
};
