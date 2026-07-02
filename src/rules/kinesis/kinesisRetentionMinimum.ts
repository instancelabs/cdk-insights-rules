import type { Rule } from '../../types';

/**
 * kinesis-retention-minimum
 *
 * At the 24-hour default retention, a consumer outage longer than a day
 * loses data permanently. Advisory — pipelines that tolerate loss can
 * suppress it.
 */
export const kinesisRetentionMinimum: Rule = {
  metadata: {
    ruleId: 'kinesis-retention-minimum',
    name: 'Kinesis Retention At Minimum',
    description:
      'Detects Kinesis streams using the minimum 24-hour retention period.',
    severity: 'LOW',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::Kinesis::Stream'],
    awsDocUrl:
      'https://docs.aws.amazon.com/streams/latest/dev/kinesis-extended-retention.html',
    remediationSteps: [
      'Increase RetentionPeriodHours (e.g. 168 for 7 days) so data survives consumer outages and can be replayed',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::Kinesis::Stream') {
        continue;
      }
      const retention = resource.Properties?.RetentionPeriodHours;
      if (
        retention === undefined ||
        (typeof retention === 'number' && retention <= 24)
      ) {
        report(resourceId, {
          issue: 'Kinesis stream uses the minimum retention period (24 hours).',
          recommendation:
            'Increase RetentionPeriodHours so a consumer outage longer than a day does not lose data permanently.',
        });
      }
    }
  },

  example: {
    flagged: `import * as kinesis from 'aws-cdk-lib/aws-kinesis';

new kinesis.CfnStream(this, 'Stream', {
  shardCount: 1,
  streamEncryption: {
    encryptionType: 'KMS',
    keyId: 'alias/aws/kinesis',
  },
});`,
    fixed: `import * as kinesis from 'aws-cdk-lib/aws-kinesis';

new kinesis.CfnStream(this, 'Stream', {
  shardCount: 1,
  retentionPeriodHours: 168,
  streamEncryption: {
    encryptionType: 'KMS',
    keyId: 'alias/aws/kinesis',
  },
});`,
  },
};
