import { isCdkInternalLogicalId } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * lambda-reserved-concurrency-missing
 *
 * Without reserved concurrency a runaway function can exhaust the account's
 * concurrency pool and throttle everything else. Advisory — most functions
 * are fine sharing the pool; set it on the ones that spike. CDK-internal
 * helper functions are exempt.
 */
export const lambdaReservedConcurrencyMissing: Rule = {
  metadata: {
    ruleId: 'lambda-reserved-concurrency-missing',
    name: 'Lambda Reserved Concurrency Missing',
    description:
      'Detects Lambda functions without reserved concurrency configured.',
    severity: 'LOW',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::Lambda::Function'],
    awsDocUrl:
      'https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html',
    remediationSteps: [
      'Set ReservedConcurrentExecutions on functions whose scaling must be bounded',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::Lambda::Function') {
        continue;
      }
      if (isCdkInternalLogicalId(resourceId)) {
        continue;
      }
      if (resource.Properties?.ReservedConcurrentExecutions === undefined) {
        report(resourceId, {
          issue: 'Lambda function has no reserved concurrency configured.',
          recommendation:
            'Consider ReservedConcurrentExecutions to bound scaling and stop a spike in this function throttling the rest of the account.',
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
});`,
    fixed: `import * as lambda from 'aws-cdk-lib/aws-lambda';

new lambda.CfnFunction(this, 'Fn', {
  handler: 'index.handler',
  role: 'arn:aws:iam::111122223333:role/lambda-role',
  runtime: 'nodejs22.x',
  code: { zipFile: 'exports.handler = async () => {};' },
  reservedConcurrentExecutions: 10,
});`,
  },
};
