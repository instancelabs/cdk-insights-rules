import type { Rule } from '../../types';

/**
 * lambda-url-auth-none — the reference rule.
 *
 * A Lambda Function URL with `AuthType: NONE` is a public, unauthenticated
 * entry point straight to your function. This is the canonical example of the
 * rule shape: read resources of a type, check one property, report a finding.
 */
export const lambdaUrlAuthNone: Rule = {
  metadata: {
    ruleId: 'lambda-url-auth-none',
    name: 'Lambda Function URL Without Authentication',
    description:
      'Detects Lambda Function URLs configured with AuthType NONE, which allows unauthenticated public invocation.',
    severity: 'HIGH',
    wafPillar: 'Security',
    resourceTypes: ['AWS::Lambda::Url'],
    awsDocUrl: 'https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html',
    remediationSteps: [
      'Set AuthType to AWS_IAM so callers are authorized with IAM SigV4',
      'Or front the function with an authenticated API Gateway / CloudFront + WAF',
    ],
    complianceFrameworks: ['SOC2', 'PCI-DSS', 'NIST'],
  },

  // Reference implementation — see README "Anatomy of a rule".
  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (
        resource.Type === 'AWS::Lambda::Url' &&
        resource.Properties?.AuthType === 'NONE'
      ) {
        report(resourceId, {
          issue:
            'Lambda Function URL uses AuthType NONE, exposing the function to unauthenticated public invocation.',
          recommendation:
            'Set AuthType to AWS_IAM, or front the function with an authenticated API Gateway / CloudFront + WAF.',
        });
      }
    }
  },

  example: {
    flagged: `import * as lambda from 'aws-cdk-lib/aws-lambda';

const fn = new lambda.Function(this, 'Fn', {
  runtime: lambda.Runtime.NODEJS_20_X,
  handler: 'index.handler',
  code: lambda.Code.fromInline('exports.handler = async () => {};'),
});
fn.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.NONE });`,
    fixed: `import * as lambda from 'aws-cdk-lib/aws-lambda';

const fn = new lambda.Function(this, 'Fn', {
  runtime: lambda.Runtime.NODEJS_20_X,
  handler: 'index.handler',
  code: lambda.Code.fromInline('exports.handler = async () => {};'),
});
fn.addFunctionUrl({ authType: lambda.FunctionUrlAuthType.AWS_IAM });`,
  },
};
