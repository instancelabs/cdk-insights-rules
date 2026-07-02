import { apigatewayDefaultEndpointEnabled } from './rules/apigateway/apigatewayDefaultEndpointEnabled.js';
import { apigatewayThrottlingMissing } from './rules/apigateway/apigatewayThrottlingMissing.js';
import { dynamodbDeletionProtectionDisabled } from './rules/dynamodb/dynamodbDeletionProtectionDisabled.js';
import { ec2Imdsv2NotEnforced } from './rules/ec2/ec2Imdsv2NotEnforced.js';
import { ecsContainerPrivileged } from './rules/ecs/ecsContainerPrivileged.js';
import { lambdaTracingDisabled } from './rules/lambda/lambdaTracingDisabled.js';
import { lambdaUrlAuthNone } from './rules/lambda/lambdaUrlAuthNone.js';
import { s3BucketVersioningDisabled } from './rules/s3/s3BucketVersioningDisabled.js';
import { sqsQueueNoDlq } from './rules/sqs/sqsQueueNoDlq.js';
import type { Rule } from './types.js';

/**
 * The open rule catalog. To add a rule, drop a file under `src/rules/<service>/`
 * that exports a `Rule`, then add it to this array. The contract test
 * (`src/rules.contract.test.ts`) enforces the invariants automatically.
 */
export const rules: Rule[] = [
  // Lambda
  lambdaUrlAuthNone,
  lambdaTracingDisabled,
  // EC2
  ec2Imdsv2NotEnforced,
  // S3
  s3BucketVersioningDisabled,
  // DynamoDB
  dynamodbDeletionProtectionDisabled,
  // ECS
  ecsContainerPrivileged,
  // SQS
  sqsQueueNoDlq,
  // API Gateway
  apigatewayDefaultEndpointEnabled,
  apigatewayThrottlingMissing,
];
