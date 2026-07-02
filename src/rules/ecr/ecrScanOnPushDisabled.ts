import { asBoolean, isIntrinsic } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * ecr-scan-on-push-disabled
 *
 * Without scan-on-push, images land in the repository unvetted and known
 * CVEs surface only when someone remembers to scan manually.
 */
export const ecrScanOnPushDisabled: Rule = {
  metadata: {
    ruleId: 'ecr-scan-on-push-disabled',
    name: 'ECR Scan On Push Disabled',
    description:
      'Detects ECR repositories without image scanning on push enabled.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::ECR::Repository'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html',
    remediationSteps: [
      'Set ImageScanningConfiguration.ScanOnPush to true (in CDK: imageScanOnPush: true)',
      'Consider registry-level enhanced scanning with Amazon Inspector for continuous rescans',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ECR::Repository') {
        continue;
      }
      const scanOnPush =
        resource.Properties?.ImageScanningConfiguration?.ScanOnPush;
      if (isIntrinsic(scanOnPush) || asBoolean(scanOnPush) === true) {
        continue;
      }
      report(resourceId, {
        issue: 'ECR repository does not have image scanning on push enabled.',
        recommendation:
          'Enable ScanOnPush in ImageScanningConfiguration so every pushed image is automatically scanned for known vulnerabilities.',
      });
    }
  },

  example: {
    flagged: `import * as ecr from 'aws-cdk-lib/aws-ecr';

new ecr.CfnRepository(this, 'Repo', {});`,
    fixed: `import * as ecr from 'aws-cdk-lib/aws-ecr';

new ecr.CfnRepository(this, 'Repo', {
  imageScanningConfiguration: { scanOnPush: true },
});`,
  },
};
