import { asBoolean } from '../../cfn.js';
import { asStatements, isPublicStatement } from '../../policy.js';
import type { Rule } from '../../types';

/**
 * secrets-manager-secret-public
 *
 * A secret's resource policy lives on a separate
 * `AWS::SecretsManager::ResourcePolicy` resource. An Allow statement granting
 * a wildcard/public principal without a scoping Condition exposes the secret
 * to any AWS account. When `BlockPublicPolicy` is true, Secrets Manager
 * rejects public policies at deploy time, so the resource is exempt.
 */
export const secretsManagerSecretPublic: Rule = {
  metadata: {
    ruleId: 'secrets-manager-secret-public',
    name: 'Secrets Manager Secret Publicly Accessible',
    description:
      'Detects Secrets Manager resource policies that grant access to a wildcard or public principal without a scoping condition.',
    severity: 'CRITICAL',
    wafPillar: 'Security',
    resourceTypes: ['AWS::SecretsManager::ResourcePolicy'],
    awsDocUrl:
      'https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-based-policies.html',
    remediationSteps: [
      'Remove wildcard/public principals from the secret resource policy',
      'Scope access to specific IAM principals or accounts',
      'Set BlockPublicPolicy to true so public policies are rejected at deploy time',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::SecretsManager::ResourcePolicy') {
        continue;
      }
      const props = resource.Properties ?? {};
      // BlockPublicPolicy makes Secrets Manager reject public policies at
      // deploy time — the secret can't actually be exposed.
      if (asBoolean(props.BlockPublicPolicy) === true) {
        continue;
      }
      const statements = asStatements(props.ResourcePolicy);
      if (statements.some(isPublicStatement)) {
        report(resourceId, {
          issue:
            'Secrets Manager resource policy grants access to a wildcard principal with no scoping condition, making the secret publicly readable.',
          recommendation:
            'Restrict the resource policy to specific IAM principals or accounts, and set BlockPublicPolicy to true as a guardrail.',
        });
      }
    }
  },

  example: {
    flagged: `import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';

new secretsmanager.CfnResourcePolicy(this, 'Policy', {
  secretId: 'arn:aws:secretsmanager:eu-west-2:111122223333:secret:my-secret',
  resourcePolicy: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: '*',
        Action: 'secretsmanager:GetSecretValue',
        Resource: '*',
      },
    ],
  },
});`,
    fixed: `import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';

new secretsmanager.CfnResourcePolicy(this, 'Policy', {
  secretId: 'arn:aws:secretsmanager:eu-west-2:111122223333:secret:my-secret',
  resourcePolicy: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::111122223333:root' },
        Action: 'secretsmanager:GetSecretValue',
        Resource: '*',
      },
    ],
  },
  blockPublicPolicy: true,
});`,
  },
};
