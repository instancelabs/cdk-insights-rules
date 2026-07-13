import type { Rule } from '../../types';

/**
 * secrets-manager-rotation-missing
 *
 * A secret with no rotation schedule is a static, long-lived credential —
 * Security Hub SecretsManager.1 territory. A secret counts as covered when
 * any AWS::SecretsManager::RotationSchedule in the template targets it
 * (SecretId via Ref/Fn::GetAtt). A schedule whose SecretId cannot be
 * resolved in-template makes coverage undecidable, so the whole rule stands
 * down for that template rather than risk false positives.
 */

// biome-ignore lint/suspicious/noExplicitAny: templates are arbitrary JSON
const resolveSecretRef = (value: any): string | null => {
  if (typeof value?.Ref === 'string') {
    return value.Ref;
  }
  const getAtt = value?.['Fn::GetAtt'];
  if (Array.isArray(getAtt) && typeof getAtt[0] === 'string') {
    return getAtt[0];
  }
  if (typeof getAtt === 'string') {
    return getAtt.split('.')[0];
  }
  return null;
};

export const secretsManagerRotationMissing: Rule = {
  metadata: {
    ruleId: 'secrets-manager-rotation-missing',
    name: 'Secrets Manager Secret Without Rotation',
    description:
      'Detects Secrets Manager secrets with no rotation schedule in the template — static credentials that never expire.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: [
      'AWS::SecretsManager::Secret',
      'AWS::SecretsManager::RotationSchedule',
    ],
    awsDocUrl:
      'https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html',
    remediationSteps: [
      'Add a rotation schedule (in CDK: secret.addRotationSchedule(...) with a hosted rotation or your own rotation Lambda)',
      'For database credentials, prefer RDS ManageMasterUserPassword, which manages and rotates the secret for you',
      'If the secret genuinely cannot rotate (third-party API key), suppress this rule on the secret to record the decision',
    ],
    complianceFrameworks: ['SOC2', 'PCI-DSS', 'CIS', 'NIST'],
  },

  check: (template, report) => {
    const resources = template.Resources ?? {};

    const rotatedSecretIds = new Set<string>();
    for (const resource of Object.values(resources)) {
      if (resource.Type !== 'AWS::SecretsManager::RotationSchedule') {
        continue;
      }
      const target = resolveSecretRef(resource.Properties?.SecretId);
      if (target === null) {
        // Rotation targeting something we cannot resolve — coverage is
        // undecidable for this template, so never flag.
        return;
      }
      rotatedSecretIds.add(target);
    }

    for (const [resourceId, resource] of Object.entries(resources)) {
      if (resource.Type !== 'AWS::SecretsManager::Secret') {
        continue;
      }
      if (rotatedSecretIds.has(resourceId)) {
        continue;
      }
      report(resourceId, {
        issue:
          'Secrets Manager secret has no rotation schedule — it is a static, long-lived credential.',
        recommendation:
          'Attach a rotation schedule (secret.addRotationSchedule(...) in CDK), or suppress this rule if the secret cannot rotate by design.',
      });
    }
  },

  example: {
    flagged: `import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';

new secretsmanager.Secret(this, 'ApiKey');`,
    fixed: `import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';

const secret = new secretsmanager.Secret(this, 'ApiKey');

new secretsmanager.CfnRotationSchedule(this, 'Rotation', {
  secretId: secret.secretArn,
  rotationLambdaArn:
    'arn:aws:lambda:eu-west-2:111122223333:function:rotate-api-key',
  rotationRules: { automaticallyAfterDays: 30 },
});`,
  },
};
