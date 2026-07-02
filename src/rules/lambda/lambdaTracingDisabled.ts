import { isCdkInternalLogicalId, isIntrinsic } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * lambda-tracing-disabled — Lambda functions without active X-Ray tracing.
 *
 * Without `TracingConfig.Mode: Active`, a function emits no distributed traces,
 * leaving latency and error investigations without segment-level visibility.
 */
export const lambdaTracingDisabled: Rule = {
  metadata: {
    ruleId: 'lambda-tracing-disabled',
    name: 'Lambda X-Ray Tracing Disabled',
    description:
      'Detects Lambda functions without active X-Ray tracing, reducing observability into latency and errors.',
    severity: 'LOW',
    wafPillar: 'Operational Excellence',
    resourceTypes: ['AWS::Lambda::Function'],
    awsDocUrl:
      'https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html',
    remediationSteps: [
      'Set TracingConfig.Mode to Active on the function',
      'Grant the function the AWSXRayDaemonWriteAccess managed policy',
    ],
    complianceFrameworks: ['SOC2'],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::Lambda::Function') {
        continue;
      }
      // CDK-internal helper functions (log-retention handlers, custom-resource
      // providers, ...) aren't configurable by the user — flagging them would
      // produce findings nobody can act on.
      if (isCdkInternalLogicalId(resourceId)) {
        continue;
      }
      const mode = resource.Properties?.TracingConfig?.Mode;
      if (mode !== 'Active' && !isIntrinsic(mode)) {
        report(resourceId, {
          issue: 'Lambda function does not have active X-Ray tracing enabled.',
          recommendation:
            'Set TracingConfig.Mode to Active to capture distributed traces for latency analysis and debugging.',
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
});`,
    fixed: `import * as lambda from 'aws-cdk-lib/aws-lambda';

const fn = new lambda.Function(this, 'Fn', {
  runtime: lambda.Runtime.NODEJS_20_X,
  handler: 'index.handler',
  code: lambda.Code.fromInline('exports.handler = async () => {};'),
  tracing: lambda.Tracing.ACTIVE,
});`,
  },
};
