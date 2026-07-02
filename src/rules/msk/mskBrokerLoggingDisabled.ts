import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * msk-broker-logging-disabled
 *
 * Broker logs are the only view into Kafka-level failures (ISR shrinkage,
 * controller elections, auth errors).
 */
export const mskBrokerLoggingDisabled: Rule = {
  metadata: {
    ruleId: 'msk-broker-logging-disabled',
    name: 'MSK Broker Logging Disabled',
    description:
      'Detects MSK clusters without broker logs to CloudWatch, Firehose, or S3.',
    severity: 'MEDIUM',
    wafPillar: 'Operational Excellence',
    resourceTypes: ['AWS::MSK::Cluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/msk/latest/developerguide/msk-logging.html',
    remediationSteps: [
      'Enable LoggingInfo.BrokerLogs to at least one destination (CloudWatchLogs, Firehose, or S3)',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::MSK::Cluster') {
        continue;
      }
      const brokerLogs = resource.Properties?.LoggingInfo?.BrokerLogs;
      const enabled =
        asBoolean(brokerLogs?.CloudWatchLogs?.Enabled) === true ||
        asBoolean(brokerLogs?.Firehose?.Enabled) === true ||
        asBoolean(brokerLogs?.S3?.Enabled) === true;
      if (!enabled) {
        report(resourceId, {
          issue: 'MSK cluster does not have broker logging configured.',
          recommendation:
            'Enable broker logs to CloudWatch, Firehose, or S3 so Kafka-level failures are observable.',
        });
      }
    }
  },

  example: {
    flagged: `import * as msk from 'aws-cdk-lib/aws-msk';

new msk.CfnCluster(this, 'Cluster', {
  clusterName: 'events',
  kafkaVersion: '3.6.0',
  numberOfBrokerNodes: 2,
  brokerNodeGroupInfo: {
    clientSubnets: ['subnet-12345678', 'subnet-87654321'],
    instanceType: 'kafka.m5.large',
  },
  clientAuthentication: { sasl: { iam: { enabled: true } } },
});`,
    fixed: `import * as msk from 'aws-cdk-lib/aws-msk';

new msk.CfnCluster(this, 'Cluster', {
  clusterName: 'events',
  kafkaVersion: '3.6.0',
  numberOfBrokerNodes: 2,
  brokerNodeGroupInfo: {
    clientSubnets: ['subnet-12345678', 'subnet-87654321'],
    instanceType: 'kafka.m5.large',
  },
  clientAuthentication: { sasl: { iam: { enabled: true } } },
  loggingInfo: {
    brokerLogs: {
      cloudWatchLogs: { enabled: true, logGroup: '/msk/events' },
    },
  },
});`,
  },
};
