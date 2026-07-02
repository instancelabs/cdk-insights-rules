import type { Rule } from '../../types';

const SENSITIVE_TERMS = [
  'password',
  'passwd',
  'pwd',
  'secret',
  'credentials?',
  'token',
  'api[_-]?key',
  'access[_-]?key',
  'encryption[_-]?key',
  'signing[_-]?key',
  'private[_-]?key',
  'bearer[_-]?token',
].join('|');

const SENSITIVE_KEY_PATTERN = new RegExp(
  `(^|[^a-z0-9])(${SENSITIVE_TERMS})(?![a-z0-9])`,
  'i'
);

const isSensitiveKey = (key: string): boolean =>
  SENSITIVE_KEY_PATTERN.test(key.replace(/([a-z0-9])([A-Z])/g, '$1_$2'));

/**
 * lambda-env-sensitive-data
 *
 * Environment variables named like secrets with literal string values are
 * readable in the console, GetFunctionConfiguration, and stack templates.
 * Only literal string values are flagged — a Ref/dynamic reference to SSM or
 * Secrets Manager resolves outside the template and is the recommended shape.
 */
export const lambdaEnvSensitiveData: Rule = {
  metadata: {
    ruleId: 'lambda-env-sensitive-data',
    name: 'Lambda Sensitive Data In Environment Variables',
    description:
      'Detects Lambda functions with sensitive-looking environment variables (passwords, API keys, tokens) set to literal values.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Lambda::Function'],
    awsDocUrl:
      'https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html',
    remediationSteps: [
      'Store the value in AWS Secrets Manager or SSM Parameter Store and fetch it at runtime (or via a dynamic reference)',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::Lambda::Function') {
        continue;
      }
      const variables = resource.Properties?.Environment?.Variables;
      if (!variables || typeof variables !== 'object') {
        continue;
      }
      const sensitive = Object.entries(variables)
        .filter(
          ([key, value]) => isSensitiveKey(key) && typeof value === 'string'
        )
        .map(([key]) => key);
      if (sensitive.length > 0) {
        report(resourceId, {
          issue: `Lambda function has sensitive-looking environment variables with literal values: ${sensitive.join(', ')}.`,
          recommendation:
            'Store secrets in AWS Secrets Manager or SSM Parameter Store and resolve them at runtime instead of embedding them in the template.',
        });
      }
    }
  },

  example: {
    flagged: `import * as lambda from 'aws-cdk-lib/aws-lambda';

new lambda.CfnFunction(this, 'Fn', {
  handler: 'index.handler',
  role: 'arn:aws:iam::111122223333:role/lambda-role',
  runtime: 'nodejs22.x',
  code: { zipFile: 'exports.handler = async () => {};' },
  environment: {
    variables: { DB_PASSWORD: 'hunter2' },
  },
});`,
    fixed: `import * as lambda from 'aws-cdk-lib/aws-lambda';

new lambda.CfnFunction(this, 'Fn', {
  handler: 'index.handler',
  role: 'arn:aws:iam::111122223333:role/lambda-role',
  runtime: 'nodejs22.x',
  code: { zipFile: 'exports.handler = async () => {};' },
  environment: {
    variables: { TABLE_NAME: 'users' },
  },
});`,
  },
};
