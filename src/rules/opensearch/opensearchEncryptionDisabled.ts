import { asBoolean, isIntrinsic } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * opensearch-encryption-disabled
 *
 * OpenSearch domains encrypt neither at rest nor node-to-node by default.
 * Covers both `AWS::OpenSearchService::Domain` and the legacy
 * `AWS::Elasticsearch::Domain`.
 */
export const opensearchEncryptionDisabled: Rule = {
  metadata: {
    ruleId: 'opensearch-encryption-disabled',
    name: 'OpenSearch Encryption Disabled',
    description:
      'Detects OpenSearch/Elasticsearch domains without encryption at rest or node-to-node encryption.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: [
      'AWS::OpenSearchService::Domain',
      'AWS::Elasticsearch::Domain',
    ],
    awsDocUrl:
      'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html',
    remediationSteps: [
      'Enable EncryptionAtRestOptions (with an optional KMS key)',
      'Enable NodeToNodeEncryptionOptions for intra-cluster traffic',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    const isDisabled = (value: unknown): boolean =>
      !isIntrinsic(value) && asBoolean(value) !== true;

    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type !== 'AWS::OpenSearchService::Domain' &&
        resource.Type !== 'AWS::Elasticsearch::Domain'
      ) {
        continue;
      }
      const props = resource.Properties ?? {};
      if (isDisabled(props.EncryptionAtRestOptions?.Enabled)) {
        report(resourceId, {
          issue: 'OpenSearch domain does not have encryption at rest enabled.',
          recommendation:
            'Enable EncryptionAtRestOptions to protect indexed data at rest with AWS KMS.',
        });
      }
      if (isDisabled(props.NodeToNodeEncryptionOptions?.Enabled)) {
        report(resourceId, {
          issue:
            'OpenSearch domain does not have node-to-node encryption enabled.',
          recommendation:
            'Enable NodeToNodeEncryptionOptions so data is encrypted in transit between cluster nodes.',
        });
      }
    }
  },

  example: {
    flagged: `import * as opensearch from 'aws-cdk-lib/aws-opensearchservice';

new opensearch.CfnDomain(this, 'Domain', {});`,
    fixed: `import * as opensearch from 'aws-cdk-lib/aws-opensearchservice';

new opensearch.CfnDomain(this, 'Domain', {
  encryptionAtRestOptions: { enabled: true },
  nodeToNodeEncryptionOptions: { enabled: true },
});`,
  },
};
