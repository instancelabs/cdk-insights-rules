import { asBoolean } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * redshift-publicly-accessible
 *
 * `PubliclyAccessible: true` gives the Redshift cluster endpoint a public IP.
 * A data warehouse is exactly the thing attackers scan for. Only a decidable
 * `true` is flagged.
 */
export const redshiftPubliclyAccessible: Rule = {
  metadata: {
    ruleId: 'redshift-publicly-accessible',
    name: 'Redshift Publicly Accessible',
    description:
      'Detects Redshift clusters with PubliclyAccessible set to true, exposing the warehouse endpoint to the internet.',
    severity: 'CRITICAL',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Redshift::Cluster'],
    awsDocUrl:
      'https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html',
    remediationSteps: [
      'Set PubliclyAccessible to false and access the cluster via VPC endpoints or a bastion host',
      'If public access is intentional (e.g. external analytics tooling), restrict source CIDRs in the security group and suppress this rule on the resource',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::Redshift::Cluster' &&
        asBoolean(resource.Properties?.PubliclyAccessible) === true
      ) {
        report(resourceId, {
          issue: 'Redshift cluster is publicly accessible from the internet.',
          recommendation:
            'Set PubliclyAccessible to false and use VPC endpoints or a bastion host for access.',
        });
      }
    }
  },

  example: {
    flagged: `import * as redshift from 'aws-cdk-lib/aws-redshift';

new redshift.CfnCluster(this, 'Cluster', {
  clusterType: 'single-node',
  dbName: 'analytics',
  masterUsername: 'admin',
  masterUserPassword: 'example-Password1',
  nodeType: 'dc2.large',
  encrypted: true,
  publiclyAccessible: true,
});`,
    fixed: `import * as redshift from 'aws-cdk-lib/aws-redshift';

new redshift.CfnCluster(this, 'Cluster', {
  clusterType: 'single-node',
  dbName: 'analytics',
  masterUsername: 'admin',
  masterUserPassword: 'example-Password1',
  nodeType: 'dc2.large',
  encrypted: true,
  publiclyAccessible: false,
});`,
  },
};
