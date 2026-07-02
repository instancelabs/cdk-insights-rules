import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * cloudtrail-logging-disabled
 *
 * A Trail with `IsLogging: false` exists but records nothing — audit history
 * silently stops. (The CDK Insights product also reports stacks that define
 * no Trail at all; that variant is inherently per-account, not per-stack, so
 * the open rule keeps only the decidable case.)
 */
export const cloudtrailLoggingDisabled: Rule = {
  metadata: {
    ruleId: 'cloudtrail-logging-disabled',
    name: 'CloudTrail Logging Disabled',
    description:
      'Detects CloudTrail trails with IsLogging set to false, silently recording no audit events.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::CloudTrail::Trail'],
    awsDocUrl:
      'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-getting-started.html',
    remediationSteps: [
      'Set IsLogging to true on the trail',
      'Alarm on CloudTrail StopLogging API calls so logging cannot be disabled unnoticed',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::CloudTrail::Trail' &&
        asBoolean(resource.Properties?.IsLogging) === false
      ) {
        report(resourceId, {
          issue:
            'CloudTrail trail has IsLogging set to false — it exists but records no audit events.',
          recommendation:
            'Set IsLogging to true; a defined-but-disabled trail gives a false sense of audit coverage.',
        });
      }
    }
  },

  example: {
    flagged: `import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';

new cloudtrail.CfnTrail(this, 'Trail', {
  s3BucketName: 'my-audit-bucket',
  isLogging: false,
});`,
    fixed: `import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';

new cloudtrail.CfnTrail(this, 'Trail', {
  s3BucketName: 'my-audit-bucket',
  isLogging: true,
});`,
  },
};
