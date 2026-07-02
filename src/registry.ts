import { apigatewayDefaultEndpointEnabled } from './rules/apigateway/apigatewayDefaultEndpointEnabled.js';
import { apigatewayThrottlingMissing } from './rules/apigateway/apigatewayThrottlingMissing.js';
import { dynamodbDeletionProtectionDisabled } from './rules/dynamodb/dynamodbDeletionProtectionDisabled.js';
import { ebsVolumeUnencrypted } from './rules/ec2/ebsVolumeUnencrypted.js';
import { ec2Imdsv2NotEnforced } from './rules/ec2/ec2Imdsv2NotEnforced.js';
import { ec2InstancePublicIp } from './rules/ec2/ec2InstancePublicIp.js';
import { securityGroupUnrestrictedIngress } from './rules/ec2/securityGroupUnrestrictedIngress.js';
import { ecsContainerPrivileged } from './rules/ecs/ecsContainerPrivileged.js';
import { iamPoliciesOverlyPermissive } from './rules/iam/iamPoliciesOverlyPermissive.js';
import { kmsKeyPolicyPublic } from './rules/kms/kmsKeyPolicyPublic.js';
import { lambdaPermissionPublic } from './rules/lambda/lambdaPermissionPublic.js';
import { lambdaTracingDisabled } from './rules/lambda/lambdaTracingDisabled.js';
import { lambdaUrlAuthNone } from './rules/lambda/lambdaUrlAuthNone.js';
import { rdsEncryptionDisabled } from './rules/rds/rdsEncryptionDisabled.js';
import { rdsPubliclyAccessible } from './rules/rds/rdsPubliclyAccessible.js';
import { s3BucketPublicAccess } from './rules/s3/s3BucketPublicAccess.js';
import { s3BucketVersioningDisabled } from './rules/s3/s3BucketVersioningDisabled.js';
import { secretsManagerSecretPublic } from './rules/secretsmanager/secretsManagerSecretPublic.js';
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
  lambdaPermissionPublic,
  lambdaTracingDisabled,
  // EC2 / EBS
  ec2Imdsv2NotEnforced,
  ec2InstancePublicIp,
  ebsVolumeUnencrypted,
  securityGroupUnrestrictedIngress,
  // S3
  s3BucketPublicAccess,
  s3BucketVersioningDisabled,
  // RDS
  rdsEncryptionDisabled,
  rdsPubliclyAccessible,
  // IAM
  iamPoliciesOverlyPermissive,
  // KMS
  kmsKeyPolicyPublic,
  // Secrets Manager
  secretsManagerSecretPublic,
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
