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
 * Block Public Access is the bucket-level guardrail against ACL/policy
 * mistakes. Since April 2023 NEW buckets get all four settings enabled by
 * default, so a bucket with no PublicAccessBlockConfiguration is protected by
 * the service default — but the protection is implicit: it does not survive
 * template reuse against legacy buckets and is invisible in review. We flag
 * missing configuration as an explicitness/hardening nudge (MEDIUM), and
 * flags decidably set to false (an active weakening) the same way.
 */
export const s3BucketPublicAccess: Rule = {
  metadata: {
    ruleId: 's3-bucket-public-access',
    name: 'S3 Bucket Public Access Not Explicitly Blocked',
    description:
      'Detects S3 buckets that do not explicitly enable all four Block Public Access settings. New buckets are protected by service defaults since April 2023; explicit configuration makes the protection visible and portable.',
    severity: 'MEDIUM',
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
            'S3 bucket does not explicitly configure PublicAccessBlockConfiguration; it relies on service defaults for public-access protection.',
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
