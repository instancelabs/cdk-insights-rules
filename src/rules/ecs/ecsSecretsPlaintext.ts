import type { Rule } from '../../types';

const SENSITIVE_ENV_PATTERN =
  /(^|_)(secret|password|passwd|pwd|credential|private_key|api_key|api_secret|auth_token|access_key|access_secret|bearer_token|jwt_secret|encryption_key|signing_key)(_|$)/i;

/** Insert boundaries into camelCase names so the pattern matches them too. */
const splitBoundaries = (name: string): string =>
  name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2');

const isSensitiveEnvName = (name: string): boolean =>
  SENSITIVE_ENV_PATTERN.test(name) ||
  SENSITIVE_ENV_PATTERN.test(splitBoundaries(name));

/**
 * ecs-secrets-plaintext
 *
 * Environment variables named like secrets (DB_PASSWORD, apiKey, ...) in a
 * task definition's plaintext `Environment` block end up readable in the
 * console, the API, and `describe-task-definition` output. ECS has a
 * dedicated `Secrets` property that resolves from Secrets Manager / SSM at
 * container start instead.
 */
export const ecsSecretsPlaintext: Rule = {
  metadata: {
    ruleId: 'ecs-secrets-plaintext',
    name: 'ECS Secrets In Plaintext Environment Variables',
    description:
      'Detects ECS task definitions with sensitive-looking environment variables (passwords, API keys, tokens) in plaintext.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::ECS::TaskDefinition'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/specifying-sensitive-data.html',
    remediationSteps: [
      'Move the value to AWS Secrets Manager or SSM Parameter Store and reference it via the container definition Secrets property (valueFrom)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ECS::TaskDefinition') {
        continue;
      }
      const containers = resource.Properties?.ContainerDefinitions;
      if (!Array.isArray(containers)) {
        continue;
      }
      const sensitive: string[] = [];
      for (const container of containers) {
        const environment = container?.Environment;
        if (!Array.isArray(environment)) {
          continue;
        }
        for (const envVar of environment) {
          const name = envVar?.Name;
          if (typeof name === 'string' && isSensitiveEnvName(name)) {
            sensitive.push(name);
          }
        }
      }
      if (sensitive.length > 0) {
        report(resourceId, {
          issue: `ECS task definition has sensitive-looking environment variables in plaintext: ${[...new Set(sensitive)].join(', ')}.`,
          recommendation:
            'Store the values in AWS Secrets Manager or SSM Parameter Store and inject them via the Secrets property (valueFrom) instead of plaintext Environment entries.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ecs from 'aws-cdk-lib/aws-ecs';

new ecs.CfnTaskDefinition(this, 'TaskDef', {
  containerDefinitions: [
    {
      name: 'app',
      image: 'public.ecr.aws/nginx/nginx:latest',
      environment: [{ name: 'DB_PASSWORD', value: 'hunter2' }],
    },
  ],
});`,
    fixed: `import * as ecs from 'aws-cdk-lib/aws-ecs';

new ecs.CfnTaskDefinition(this, 'TaskDef', {
  containerDefinitions: [
    {
      name: 'app',
      image: 'public.ecr.aws/nginx/nginx:latest',
      secrets: [
        {
          name: 'DB_PASSWORD',
          valueFrom:
            'arn:aws:secretsmanager:eu-west-2:111122223333:secret:db-password',
        },
      ],
    },
  ],
});`,
  },
};
