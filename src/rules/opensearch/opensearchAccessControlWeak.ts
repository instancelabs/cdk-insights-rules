import { asBoolean, isIntrinsic } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * opensearch-access-control-weak
 *
 * Fine-grained access control (document/field-level security) and VPC
 * deployment are the two structural access controls for a domain.
 */
export const opensearchAccessControlWeak: Rule = {
  metadata: {
    ruleId: 'opensearch-access-control-weak',
    name: 'OpenSearch Access Control Weak',
    description:
      'Detects OpenSearch domains without fine-grained access control or VPC deployment.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: [
      'AWS::OpenSearchService::Domain',
      'AWS::Elasticsearch::Domain',
    ],
    awsDocUrl:
      'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/fgac.html',
    remediationSteps: [
      'Enable AdvancedSecurityOptions for fine-grained access control',
      'Deploy the domain into a VPC via VPCOptions',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
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
      const fgacEnabled = props.AdvancedSecurityOptions?.Enabled;
      if (!isIntrinsic(fgacEnabled) && asBoolean(fgacEnabled) !== true) {
        report(resourceId, {
          issue:
            'OpenSearch domain does not have fine-grained access control enabled.',
          recommendation:
            'Enable AdvancedSecurityOptions for document-level and field-level security backed by IAM or the internal user database.',
        });
      }
      const subnetIds = props.VPCOptions?.SubnetIds;
      if (!Array.isArray(subnetIds) || subnetIds.length === 0) {
        report(resourceId, {
          issue: 'OpenSearch domain is not deployed within a VPC.',
          recommendation:
            'Configure VPCOptions with subnet IDs so the domain is network-isolated rather than publicly addressable.',
        });
      }
    }
  },

  example: {
    flagged: `import * as opensearch from 'aws-cdk-lib/aws-opensearchservice';

new opensearch.CfnDomain(this, 'Domain', {
  encryptionAtRestOptions: { enabled: true },
  nodeToNodeEncryptionOptions: { enabled: true },
});`,
    fixed: `import * as opensearch from 'aws-cdk-lib/aws-opensearchservice';

new opensearch.CfnDomain(this, 'Domain', {
  encryptionAtRestOptions: { enabled: true },
  nodeToNodeEncryptionOptions: { enabled: true },
  advancedSecurityOptions: {
    enabled: true,
    internalUserDatabaseEnabled: true,
    masterUserOptions: {
      masterUserName: 'admin',
      masterUserPassword: 'example-Password1!',
    },
  },
  vpcOptions: {
    subnetIds: ['subnet-12345678'],
  },
});`,
  },
};
