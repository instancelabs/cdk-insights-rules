import { isCdkInternalLogicalId } from '../../cfn.js';
import type { Rule } from '../../types';

/**
 * lambda-memory-optimization
 *
 * Memory above 1 GB is often a copy-paste default rather than a measured
 * need; Lambda bills memory x duration. Advisory — CPU-bound functions
 * legitimately need it (more memory = more vCPU), so suppress where sized
 * deliberately.
 */
export const lambdaMemoryOptimization: Rule = {
  metadata: {
    ruleId: 'lambda-memory-optimization',
    name: 'Lambda Memory Allocation High',
    description:
      'Detects Lambda functions with memory allocations above 1024 MB.',
    severity: 'MEDIUM',
    wafPillar: 'Cost Optimization',
    resourceTypes: ['AWS::Lambda::Function'],
    awsDocUrl:
      'https://docs.aws.amazon.com/lambda/latest/dg/configuration-function-common.html#configuration-memory-console',
    remediationSteps: [
      'Right-size memory with AWS Lambda Power Tuning; suppress this rule where high memory is a measured need',
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
      const memory = resource.Properties?.MemorySize;
      if (typeof memory === 'number' && memory > 1024) {
        report(resourceId, {
          issue: `Lambda function allocates ${memory} MB of memory.`,
          recommendation:
            'Verify the allocation with Lambda Power Tuning — memory is billed per millisecond, and oversized functions pay for headroom they never use.',
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
  memorySize: 3008,
});`,
    fixed: `import * as lambda from 'aws-cdk-lib/aws-lambda';

new lambda.CfnFunction(this, 'Fn', {
  handler: 'index.handler',
  role: 'arn:aws:iam::111122223333:role/lambda-role',
  runtime: 'nodejs22.x',
  code: { zipFile: 'exports.handler = async () => {};' },
  memorySize: 512,
});`,
  },
};
