import type { Rule } from '../../types';

/**
 * ecr-lifecycle-policy-missing
 *
 * Without a lifecycle policy every pushed image is stored forever — CI
 * pipelines accumulate storage cost indefinitely.
 */
export const ecrLifecyclePolicyMissing: Rule = {
  metadata: {
    ruleId: 'ecr-lifecycle-policy-missing',
    name: 'ECR Lifecycle Policy Missing',
    description: 'Detects ECR repositories without a lifecycle policy.',
    severity: 'MEDIUM',
    wafPillar: 'Cost Optimization',
    resourceTypes: ['AWS::ECR::Repository'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html',
    remediationSteps: [
      'Add a LifecyclePolicy expiring untagged images and capping tagged image count',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::ECR::Repository' &&
        !resource.Properties?.LifecyclePolicy?.LifecyclePolicyText
      ) {
        report(resourceId, {
          issue: 'ECR repository has no lifecycle policy configured.',
          recommendation:
            'Add a lifecycle policy so old and untagged images are cleaned up instead of accumulating storage cost forever.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ecr from 'aws-cdk-lib/aws-ecr';

new ecr.CfnRepository(this, 'Repo', {
  imageScanningConfiguration: { scanOnPush: true },
  imageTagMutability: 'IMMUTABLE',
});`,
    fixed: `import * as ecr from 'aws-cdk-lib/aws-ecr';

new ecr.CfnRepository(this, 'Repo', {
  imageScanningConfiguration: { scanOnPush: true },
  imageTagMutability: 'IMMUTABLE',
  lifecyclePolicy: {
    lifecyclePolicyText: JSON.stringify({
      rules: [
        {
          rulePriority: 1,
          description: 'expire untagged images',
          selection: {
            tagStatus: 'untagged',
            countType: 'sinceImagePushed',
            countUnit: 'days',
            countNumber: 14,
          },
          action: { type: 'expire' },
        },
      ],
    }),
  },
});`,
  },
};
