import type { Rule } from '../../types';

const SSL_URL_PATTERN =
  /(?:(?:use|require)?ssl\s*=\s*true|encrypt\s*=\s*true|sslmode\s*=\s*(?:require|verify-ca|verify-full)|(?:^|[^a-z])tcps:)/i;

/**
 * glue-connection-network-isolation
 *
 * A JDBC connection without a VPC subnet runs over shared networking, and a
 * JDBC URL without SSL parameters may move data in plaintext.
 */
export const glueConnectionNetworkIsolation: Rule = {
  metadata: {
    ruleId: 'glue-connection-network-isolation',
    name: 'Glue Connection Network Isolation',
    description:
      'Detects Glue JDBC connections without VPC network isolation or SSL enforcement.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Glue::Connection'],
    awsDocUrl:
      'https://docs.aws.amazon.com/glue/latest/dg/setup-vpc-for-glue-access.html',
    remediationSteps: [
      'Configure PhysicalConnectionRequirements with SubnetId and SecurityGroupIdList',
      'Set JDBC_ENFORCE_SSL (or SSL parameters in the JDBC URL) to encrypt data in transit',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::Glue::Connection') {
        continue;
      }
      const input = resource.Properties?.ConnectionInput;
      if (input?.ConnectionType !== 'JDBC') {
        continue;
      }
      if (!input?.PhysicalConnectionRequirements?.SubnetId) {
        report(resourceId, {
          issue: 'Glue JDBC connection does not specify a VPC subnet.',
          recommendation:
            'Configure PhysicalConnectionRequirements with SubnetId and SecurityGroupIdList for network isolation.',
        });
      }
      const connectionProperties = input?.ConnectionProperties;
      const jdbcUrl = connectionProperties?.JDBC_CONNECTION_URL;
      const enforceSsl =
        String(connectionProperties?.JDBC_ENFORCE_SSL).toLowerCase() === 'true';
      const urlEnforcesSsl =
        typeof jdbcUrl === 'string' && SSL_URL_PATTERN.test(jdbcUrl);
      if (!enforceSsl && !urlEnforcesSsl) {
        report(resourceId, {
          issue: 'Glue JDBC connection may not enforce SSL.',
          recommendation:
            'Set JDBC_ENFORCE_SSL to true (or include SSL parameters in the JDBC URL) so data is encrypted in transit.',
        });
      }
    }
  },

  example: {
    flagged: `import * as glue from 'aws-cdk-lib/aws-glue';

new glue.CfnConnection(this, 'Connection', {
  catalogId: '111122223333',
  connectionInput: {
    connectionType: 'JDBC',
    connectionProperties: {
      JDBC_CONNECTION_URL: 'jdbc:mysql://db.internal:3306/analytics',
    },
  },
});`,
    fixed: `import * as glue from 'aws-cdk-lib/aws-glue';

new glue.CfnConnection(this, 'Connection', {
  catalogId: '111122223333',
  connectionInput: {
    connectionType: 'JDBC',
    connectionProperties: {
      JDBC_CONNECTION_URL: 'jdbc:mysql://db.internal:3306/analytics',
      JDBC_ENFORCE_SSL: 'true',
    },
    physicalConnectionRequirements: {
      subnetId: 'subnet-12345678',
      securityGroupIdList: ['sg-12345678'],
    },
  },
});`,
  },
};
