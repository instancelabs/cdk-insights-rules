import type { Rule } from '../../types';

/**
 * Runtimes that have reached (or been announced for) end-of-life, mapped to
 * the recommended replacement. Mirrors the CDK Insights product table.
 */
const DEPRECATED_RUNTIMES: Record<string, string> = {
  nodejs: 'nodejs22.x',
  'nodejs4.3': 'nodejs22.x',
  'nodejs4.3-edge': 'nodejs22.x',
  'nodejs6.10': 'nodejs22.x',
  'nodejs8.10': 'nodejs22.x',
  'nodejs10.x': 'nodejs22.x',
  'nodejs12.x': 'nodejs22.x',
  'nodejs14.x': 'nodejs22.x',
  'nodejs16.x': 'nodejs22.x',
  'nodejs18.x': 'nodejs22.x',
  'python2.7': 'python3.13',
  'python3.6': 'python3.13',
  'python3.7': 'python3.13',
  'python3.8': 'python3.13',
  'python3.9': 'python3.13',
  java8: 'java21',
  'java8.al2': 'java21',
  // java11 deliberately absent: AWS has not announced Lambda deprecation for
  // it (Corretto 11 support runs to 2027) — flagging it would overclaim.
  'dotnetcore1.0': 'dotnet8',
  'dotnetcore2.0': 'dotnet8',
  'dotnetcore2.1': 'dotnet8',
  'dotnetcore3.1': 'dotnet8',
  'dotnet5.0': 'dotnet8',
  dotnet6: 'dotnet8',
  'ruby2.5': 'ruby3.3',
  'ruby2.7': 'ruby3.3',
  'go1.x': 'provided.al2023',
};

/**
 * lambda-runtime-deprecated
 *
 * A function on a deprecated runtime no longer receives security patches, and
 * AWS progressively blocks updates and then creation for it.
 */
export const lambdaRuntimeDeprecated: Rule = {
  metadata: {
    ruleId: 'lambda-runtime-deprecated',
    name: 'Lambda Runtime Deprecated',
    description:
      'Detects Lambda functions on deprecated runtimes that no longer receive security patches.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Lambda::Function'],
    awsDocUrl:
      'https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html',
    remediationSteps: [
      'Upgrade the function to the current runtime for its language (see the finding for the recommended target)',
    ],
    complianceFrameworks: ['SOC2', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::Lambda::Function') {
        continue;
      }
      const runtime = resource.Properties?.Runtime;
      if (typeof runtime !== 'string') {
        continue;
      }
      const replacement = DEPRECATED_RUNTIMES[runtime];
      if (replacement) {
        report(resourceId, {
          issue: `Lambda function uses deprecated runtime "${runtime}", which no longer receives security patches.`,
          recommendation: `Upgrade to "${replacement}" for continued security patches and support.`,
        });
      }
    }
  },

  example: {
    flagged: `import * as lambda from 'aws-cdk-lib/aws-lambda';

new lambda.CfnFunction(this, 'Fn', {
  functionName: 'legacy',
  handler: 'index.handler',
  role: 'arn:aws:iam::111122223333:role/lambda-role',
  runtime: 'nodejs14.x',
  code: { zipFile: 'exports.handler = async () => {};' },
});`,
    fixed: `import * as lambda from 'aws-cdk-lib/aws-lambda';

new lambda.CfnFunction(this, 'Fn', {
  functionName: 'legacy',
  handler: 'index.handler',
  role: 'arn:aws:iam::111122223333:role/lambda-role',
  runtime: 'nodejs22.x',
  code: { zipFile: 'exports.handler = async () => {};' },
});`,
  },
};
