import type { Rule } from '../../types';

/**
 * ecr-mutable-tags
 *
 * Mutable tags let `:v1.2.3` be silently repointed at a different image —
 * a supply-chain risk and a reproducibility problem.
 */
export const ecrMutableTags: Rule = {
  metadata: {
    ruleId: 'ecr-mutable-tags',
    name: 'ECR Mutable Image Tags',
    description:
      'Detects ECR repositories that allow image tags to be overwritten.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::ECR::Repository'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html',
    remediationSteps: [
      'Set ImageTagMutability to IMMUTABLE (or IMMUTABLE_WITH_EXCLUSION for tags like "latest")',
    ],
    complianceFrameworks: ['SOC2', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ECR::Repository') {
        continue;
      }
      const mutability = resource.Properties?.ImageTagMutability;
      const isImmutable =
        mutability === 'IMMUTABLE' || mutability === 'IMMUTABLE_WITH_EXCLUSION';
      if (!isImmutable && typeof mutability !== 'object') {
        report(resourceId, {
          issue:
            'ECR repository allows mutable image tags — a pushed tag can be silently repointed at a different image.',
          recommendation:
            'Set ImageTagMutability to IMMUTABLE so deployed tags always reference the image they were built as.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ecr from 'aws-cdk-lib/aws-ecr';

new ecr.CfnRepository(this, 'Repo', {
  imageScanningConfiguration: { scanOnPush: true },
});`,
    fixed: `import * as ecr from 'aws-cdk-lib/aws-ecr';

new ecr.CfnRepository(this, 'Repo', {
  imageScanningConfiguration: { scanOnPush: true },
  imageTagMutability: 'IMMUTABLE',
});`,
  },
};
