import { apigatewayDefaultEndpointEnabled } from './rules/apigateway/apigatewayDefaultEndpointEnabled.js';
import { apigatewayMethodAuthMissing } from './rules/apigateway/apigatewayMethodAuthMissing.js';
import { apigatewayThrottlingMissing } from './rules/apigateway/apigatewayThrottlingMissing.js';
import { autoscalingLaunchConfigPublicIp } from './rules/autoscaling/autoscalingLaunchConfigPublicIp.js';
import { cloudfrontHttpsOnly } from './rules/cloudfront/cloudfrontHttpsOnly.js';
import { cloudfrontTlsOutdated } from './rules/cloudfront/cloudfrontTlsOutdated.js';
import { cloudtrailLoggingDisabled } from './rules/cloudtrail/cloudtrailLoggingDisabled.js';
import { cognitoMfaDisabled } from './rules/cognito/cognitoMfaDisabled.js';
import { cognitoPasswordPolicyWeak } from './rules/cognito/cognitoPasswordPolicyWeak.js';
import { dynamodbDeletionProtectionDisabled } from './rules/dynamodb/dynamodbDeletionProtectionDisabled.js';
import { dynamodbEncryptionAwsOwnedKey } from './rules/dynamodb/dynamodbEncryptionAwsOwnedKey.js';
import { ebsVolumeUnencrypted } from './rules/ec2/ebsVolumeUnencrypted.js';
import { ec2Imdsv2NotEnforced } from './rules/ec2/ec2Imdsv2NotEnforced.js';
import { ec2InstancePublicIp } from './rules/ec2/ec2InstancePublicIp.js';
import { ec2SubnetAutoPublicIp } from './rules/ec2/ec2SubnetAutoPublicIp.js';
import { securityGroupUnrestrictedIngress } from './rules/ec2/securityGroupUnrestrictedIngress.js';
import { ecrMutableTags } from './rules/ecr/ecrMutableTags.js';
import { ecrScanOnPushDisabled } from './rules/ecr/ecrScanOnPushDisabled.js';
import { ecsContainerPrivileged } from './rules/ecs/ecsContainerPrivileged.js';
import { ecsSecretsPlaintext } from './rules/ecs/ecsSecretsPlaintext.js';
import { efsEncryptionDisabled } from './rules/efs/efsEncryptionDisabled.js';
import { eksControlPlaneLoggingDisabled } from './rules/eks/eksControlPlaneLoggingDisabled.js';
import { eksPublicEndpointUnrestricted } from './rules/eks/eksPublicEndpointUnrestricted.js';
import { eksSecretsEncryptionDisabled } from './rules/eks/eksSecretsEncryptionDisabled.js';
import { elasticacheAuthTokenMissing } from './rules/elasticache/elasticacheAuthTokenMissing.js';
import { elasticacheEncryptionDisabled } from './rules/elasticache/elasticacheEncryptionDisabled.js';
import { elbHttpsListenersMissing } from './rules/elb/elbHttpsListenersMissing.js';
import { elbLoggingDisabled } from './rules/elb/elbLoggingDisabled.js';
import { eventbridgeBusPolicyWildcardPrincipal } from './rules/eventbridge/eventbridgeBusPolicyWildcardPrincipal.js';
import { iamPoliciesOverlyPermissive } from './rules/iam/iamPoliciesOverlyPermissive.js';
import { iamUserDirectPolicies } from './rules/iam/iamUserDirectPolicies.js';
import { kinesisEncryptionDisabled } from './rules/kinesis/kinesisEncryptionDisabled.js';
import { kmsKeyPolicyPublic } from './rules/kms/kmsKeyPolicyPublic.js';
import { kmsKeyPolicySelfLockout } from './rules/kms/kmsKeyPolicySelfLockout.js';
import { lambdaEnvSensitiveData } from './rules/lambda/lambdaEnvSensitiveData.js';
import { lambdaPermissionPublic } from './rules/lambda/lambdaPermissionPublic.js';
import { lambdaPermissionServiceUnrestricted } from './rules/lambda/lambdaPermissionServiceUnrestricted.js';
import { lambdaRuntimeDeprecated } from './rules/lambda/lambdaRuntimeDeprecated.js';
import { lambdaTracingDisabled } from './rules/lambda/lambdaTracingDisabled.js';
import { lambdaUrlAuthNone } from './rules/lambda/lambdaUrlAuthNone.js';
import { mskClientAuthenticationMissing } from './rules/msk/mskClientAuthenticationMissing.js';
import { mskEncryptionWeak } from './rules/msk/mskEncryptionWeak.js';
import { opensearchEncryptionDisabled } from './rules/opensearch/opensearchEncryptionDisabled.js';
import { rdsEncryptionDisabled } from './rules/rds/rdsEncryptionDisabled.js';
import { rdsPubliclyAccessible } from './rules/rds/rdsPubliclyAccessible.js';
import { redshiftEncryptionDisabled } from './rules/redshift/redshiftEncryptionDisabled.js';
import { redshiftPubliclyAccessible } from './rules/redshift/redshiftPubliclyAccessible.js';
import { s3BucketAccessLoggingDisabled } from './rules/s3/s3BucketAccessLoggingDisabled.js';
import { s3BucketPolicyNonSsl } from './rules/s3/s3BucketPolicyNonSsl.js';
import { s3BucketPolicySelfLockout } from './rules/s3/s3BucketPolicySelfLockout.js';
import { s3BucketPublicAccess } from './rules/s3/s3BucketPublicAccess.js';
import { s3BucketVersioningDisabled } from './rules/s3/s3BucketVersioningDisabled.js';
import { secretsManagerSecretPublic } from './rules/secretsmanager/secretsManagerSecretPublic.js';
import { snsEncryptionDisabled } from './rules/sns/snsEncryptionDisabled.js';
import { snsTopicPolicySelfLockout } from './rules/sns/snsTopicPolicySelfLockout.js';
import { sqsEncryptionDisabled } from './rules/sqs/sqsEncryptionDisabled.js';
import { sqsQueueNoDlq } from './rules/sqs/sqsQueueNoDlq.js';
import { sqsQueuePolicySelfLockout } from './rules/sqs/sqsQueuePolicySelfLockout.js';
import { vpcFlowLogsMissing } from './rules/vpc/vpcFlowLogsMissing.js';
import { wafWebAclMisconfigured } from './rules/waf/wafWebAclMisconfigured.js';
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
  lambdaPermissionServiceUnrestricted,
  lambdaRuntimeDeprecated,
  lambdaEnvSensitiveData,
  lambdaTracingDisabled,
  // EC2 / EBS
  ec2Imdsv2NotEnforced,
  ec2InstancePublicIp,
  ec2SubnetAutoPublicIp,
  ebsVolumeUnencrypted,
  securityGroupUnrestrictedIngress,
  // S3
  s3BucketPublicAccess,
  s3BucketVersioningDisabled,
  s3BucketPolicySelfLockout,
  s3BucketPolicyNonSsl,
  s3BucketAccessLoggingDisabled,
  // RDS
  rdsEncryptionDisabled,
  rdsPubliclyAccessible,
  // IAM
  iamPoliciesOverlyPermissive,
  iamUserDirectPolicies,
  // KMS
  kmsKeyPolicyPublic,
  kmsKeyPolicySelfLockout,
  // Secrets Manager
  secretsManagerSecretPublic,
  // SNS
  snsEncryptionDisabled,
  snsTopicPolicySelfLockout,
  // EventBridge
  eventbridgeBusPolicyWildcardPrincipal,
  // Redshift
  redshiftPubliclyAccessible,
  redshiftEncryptionDisabled,
  // Kinesis / EFS / ElastiCache
  kinesisEncryptionDisabled,
  efsEncryptionDisabled,
  elasticacheEncryptionDisabled,
  elasticacheAuthTokenMissing,
  // VPC
  vpcFlowLogsMissing,
  // WAF
  wafWebAclMisconfigured,
  // CloudFront / CloudTrail
  cloudfrontHttpsOnly,
  cloudfrontTlsOutdated,
  cloudtrailLoggingDisabled,
  // Cognito
  cognitoPasswordPolicyWeak,
  cognitoMfaDisabled,
  // ECR
  ecrScanOnPushDisabled,
  ecrMutableTags,
  // EKS
  eksPublicEndpointUnrestricted,
  eksSecretsEncryptionDisabled,
  eksControlPlaneLoggingDisabled,
  // ELB
  elbHttpsListenersMissing,
  elbLoggingDisabled,
  // MSK
  mskClientAuthenticationMissing,
  mskEncryptionWeak,
  // OpenSearch
  opensearchEncryptionDisabled,
  // AutoScaling
  autoscalingLaunchConfigPublicIp,
  // DynamoDB
  dynamodbDeletionProtectionDisabled,
  dynamodbEncryptionAwsOwnedKey,
  // ECS
  ecsContainerPrivileged,
  ecsSecretsPlaintext,
  // SQS
  sqsQueueNoDlq,
  sqsEncryptionDisabled,
  sqsQueuePolicySelfLockout,
  // API Gateway
  apigatewayMethodAuthMissing,
  apigatewayDefaultEndpointEnabled,
  apigatewayThrottlingMissing,
];
