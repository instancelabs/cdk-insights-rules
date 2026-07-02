import { asBoolean, isIntrinsic } from '../../cfn.js';
import type { Rule } from '../../types';

const PUBLIC_ACCESS_FLAGS = [
  'BlockPublicAcls',
  'BlockPublicPolicy',
  'IgnorePublicAcls',
  'RestrictPublicBuckets',
] as const;

/**
 * s3-bucket-public-access
 *
 * Public S3 buckets are the classic cloud breach. Block Public Access is the
 * account/bucket-level guardrail: with all four settings on, a bucket cannot
 * be made public by an ACL or policy mistake. We flag buckets with no
 * PublicAccessBlockConfiguration at all, and buckets where any of the four
 * settings is decidably not enabled.
 */
export const s3BucketPublicAccess: Rule = {
  metadata: {
    ruleId: 's3-bucket-public-access',
    name: 'S3 Bucket Public Access Not Blocked',
    description:
      'Detects S3 buckets without a full Block Public Access configuration, leaving them exposable via ACLs or bucket policies.',
    severity: 'CRITICAL',
    wafPillar: 'Security',
    resourceTypes: ['AWS::S3::Bucket'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html',
    remediationSteps: [
      'Set PublicAccessBlockConfiguration with BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, and RestrictPublicBuckets all true (in CDK: blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL)',
      'Review bucket policies and ACLs for intended public access; serve public content via CloudFront instead',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::S3::Bucket') {
        continue;
      }
      const publicAccessBlock =
        resource.Properties?.PublicAccessBlockConfiguration;

      if (!publicAccessBlock) {
        report(resourceId, {
          issue:
            'S3 bucket has no PublicAccessBlockConfiguration, so an ACL or bucket-policy mistake can make it public.',
          recommendation:
            'Configure PublicAccessBlockConfiguration with BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, and RestrictPublicBuckets all set to true (in CDK: blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL).',
        });
        continue;
      }

      // Flags set via intrinsics are undecidable — never flag those.
      const disabled = PUBLIC_ACCESS_FLAGS.filter(
        (flag) =>
          !isIntrinsic(publicAccessBlock[flag]) &&
          asBoolean(publicAccessBlock[flag]) !== true
      );
      if (disabled.length > 0) {
        report(resourceId, {
          issue: `S3 bucket does not fully block public access: ${disabled.join(', ')} not enabled.`,
          recommendation:
            'Set all four Block Public Access settings to true so the bucket cannot be exposed via ACLs or bucket policies.',
        });
      }
    }
  },

  example: {
    flagged: `import * as s3 from 'aws-cdk-lib/aws-s3';

new s3.Bucket(this, 'Bucket');`,
    fixed: `import * as s3 from 'aws-cdk-lib/aws-s3';

new s3.Bucket(this, 'Bucket', {
  blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
});`,
  },
};
