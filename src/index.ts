export { defineRule } from './defineRule.js';
export { rules } from './registry.js';
export { runRules } from './runRules.js';

// Individual rules, so consumers can cherry-pick and tree-shake instead of
// pulling the whole catalog.
export { apigatewayDefaultEndpointEnabled } from './rules/apigateway/apigatewayDefaultEndpointEnabled.js';
export { apigatewayThrottlingMissing } from './rules/apigateway/apigatewayThrottlingMissing.js';
export { dynamodbDeletionProtectionDisabled } from './rules/dynamodb/dynamodbDeletionProtectionDisabled.js';
export { ec2Imdsv2NotEnforced } from './rules/ec2/ec2Imdsv2NotEnforced.js';
export { ecsContainerPrivileged } from './rules/ecs/ecsContainerPrivileged.js';
export { lambdaTracingDisabled } from './rules/lambda/lambdaTracingDisabled.js';
export { lambdaUrlAuthNone } from './rules/lambda/lambdaUrlAuthNone.js';
export { s3BucketVersioningDisabled } from './rules/s3/s3BucketVersioningDisabled.js';
export { sqsQueueNoDlq } from './rules/sqs/sqsQueueNoDlq.js';

export type {
  CfnResource,
  CfnTemplate,
  Finding,
  ReportFinding,
  Rule,
  RuleCheck,
  RuleExample,
  RuleMetadata,
  Severity,
  WafPillar,
} from './types.js';
