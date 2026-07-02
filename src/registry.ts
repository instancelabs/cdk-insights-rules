import { acmCertificateEmailValidation } from './rules/acm/acmCertificateEmailValidation.js';
import { apigatewayDefaultEndpointEnabled } from './rules/apigateway/apigatewayDefaultEndpointEnabled.js';
import { apigatewayMethodAuthMissing } from './rules/apigateway/apigatewayMethodAuthMissing.js';
import { apigatewayThrottlingMissing } from './rules/apigateway/apigatewayThrottlingMissing.js';
import { appsyncApiKeyAuth } from './rules/appsync/appsyncApiKeyAuth.js';
import { appsyncWafMissing } from './rules/appsync/appsyncWafMissing.js';
import { autoscalingGroupNoElbHealthcheck } from './rules/autoscaling/autoscalingGroupNoElbHealthcheck.js';
import { autoscalingLaunchConfigPublicIp } from './rules/autoscaling/autoscalingLaunchConfigPublicIp.js';
import { backupPlanMisconfigured } from './rules/backup/backupPlanMisconfigured.js';
import { backupVaultHardening } from './rules/backup/backupVaultHardening.js';
import { cloudfrontHttpsOnly } from './rules/cloudfront/cloudfrontHttpsOnly.js';
import { cloudfrontLoggingDisabled } from './rules/cloudfront/cloudfrontLoggingDisabled.js';
import { cloudfrontTlsOutdated } from './rules/cloudfront/cloudfrontTlsOutdated.js';
import { cloudfrontWafMissing } from './rules/cloudfront/cloudfrontWafMissing.js';
import { cloudtrailLoggingDisabled } from './rules/cloudtrail/cloudtrailLoggingDisabled.js';
import { cloudwatchLogsEncryptionDisabled } from './rules/cloudwatch/cloudwatchLogsEncryptionDisabled.js';
import { cognitoAdvancedSecurityDisabled } from './rules/cognito/cognitoAdvancedSecurityDisabled.js';
import { cognitoMfaDisabled } from './rules/cognito/cognitoMfaDisabled.js';
import { cognitoPasswordPolicyWeak } from './rules/cognito/cognitoPasswordPolicyWeak.js';
import { dynamodbDeletionProtectionDisabled } from './rules/dynamodb/dynamodbDeletionProtectionDisabled.js';
import { dynamodbEncryptionAwsOwnedKey } from './rules/dynamodb/dynamodbEncryptionAwsOwnedKey.js';
import { dynamodbPitrDisabled } from './rules/dynamodb/dynamodbPitrDisabled.js';
import { ebsVolumeUnencrypted } from './rules/ec2/ebsVolumeUnencrypted.js';
import { ec2Imdsv2NotEnforced } from './rules/ec2/ec2Imdsv2NotEnforced.js';
import { ec2InstancePublicIp } from './rules/ec2/ec2InstancePublicIp.js';
import { ec2SubnetAutoPublicIp } from './rules/ec2/ec2SubnetAutoPublicIp.js';
import { securityGroupUnrestrictedIngress } from './rules/ec2/securityGroupUnrestrictedIngress.js';
import { ecrMutableTags } from './rules/ecr/ecrMutableTags.js';
import { ecrScanOnPushDisabled } from './rules/ecr/ecrScanOnPushDisabled.js';
import { ecsContainerPrivileged } from './rules/ecs/ecsContainerPrivileged.js';
import { ecsResourcesMissing } from './rules/ecs/ecsResourcesMissing.js';
import { ecsSecretsPlaintext } from './rules/ecs/ecsSecretsPlaintext.js';
import { ecsServiceConnectAccessLogsMissing } from './rules/ecs/ecsServiceConnectAccessLogsMissing.js';
import { efsEncryptionDisabled } from './rules/efs/efsEncryptionDisabled.js';
import { eksControlPlaneLoggingDisabled } from './rules/eks/eksControlPlaneLoggingDisabled.js';
import { eksPublicEndpointUnrestricted } from './rules/eks/eksPublicEndpointUnrestricted.js';
import { eksSecretsEncryptionDisabled } from './rules/eks/eksSecretsEncryptionDisabled.js';
import { elasticacheAuthTokenMissing } from './rules/elasticache/elasticacheAuthTokenMissing.js';
import { elasticacheEncryptionDisabled } from './rules/elasticache/elasticacheEncryptionDisabled.js';
import { elasticacheFailoverDisabled } from './rules/elasticache/elasticacheFailoverDisabled.js';
import { elbDeletionProtectionDisabled } from './rules/elb/elbDeletionProtectionDisabled.js';
import { elbHttpsListenersMissing } from './rules/elb/elbHttpsListenersMissing.js';
import { elbLoggingDisabled } from './rules/elb/elbLoggingDisabled.js';
import { eventbridgeBusPolicyWildcardPrincipal } from './rules/eventbridge/eventbridgeBusPolicyWildcardPrincipal.js';
import { eventbridgeRuleNoTargets } from './rules/eventbridge/eventbridgeRuleNoTargets.js';
import { eventbridgeTargetDlqMissing } from './rules/eventbridge/eventbridgeTargetDlqMissing.js';
import { glueConnectionNetworkIsolation } from './rules/glue/glueConnectionNetworkIsolation.js';
import { glueJobEncryptionMissing } from './rules/glue/glueJobEncryptionMissing.js';
import { iamCrossAccountTrust } from './rules/iam/iamCrossAccountTrust.js';
import { iamPermissionBoundaryMissing } from './rules/iam/iamPermissionBoundaryMissing.js';
import { iamPoliciesOverlyPermissive } from './rules/iam/iamPoliciesOverlyPermissive.js';
import { iamUserDirectPolicies } from './rules/iam/iamUserDirectPolicies.js';
import { kinesisEncryptionDisabled } from './rules/kinesis/kinesisEncryptionDisabled.js';
import { kinesisRetentionMinimum } from './rules/kinesis/kinesisRetentionMinimum.js';
import { kmsKeyPolicyPublic } from './rules/kms/kmsKeyPolicyPublic.js';
import { kmsKeyPolicySelfLockout } from './rules/kms/kmsKeyPolicySelfLockout.js';
import { lambdaDlqMissing } from './rules/lambda/lambdaDlqMissing.js';
import { lambdaEnvSensitiveData } from './rules/lambda/lambdaEnvSensitiveData.js';
import { lambdaPermissionPublic } from './rules/lambda/lambdaPermissionPublic.js';
import { lambdaPermissionServiceUnrestricted } from './rules/lambda/lambdaPermissionServiceUnrestricted.js';
import { lambdaReservedConcurrencyMissing } from './rules/lambda/lambdaReservedConcurrencyMissing.js';
import { lambdaRuntimeDeprecated } from './rules/lambda/lambdaRuntimeDeprecated.js';
import { lambdaTracingDisabled } from './rules/lambda/lambdaTracingDisabled.js';
import { lambdaUrlAuthNone } from './rules/lambda/lambdaUrlAuthNone.js';
import { mskClientAuthenticationMissing } from './rules/msk/mskClientAuthenticationMissing.js';
import { mskEncryptionWeak } from './rules/msk/mskEncryptionWeak.js';
import { opensearchAccessControlWeak } from './rules/opensearch/opensearchAccessControlWeak.js';
import { opensearchEncryptionDisabled } from './rules/opensearch/opensearchEncryptionDisabled.js';
import { opensearchLoggingDisabled } from './rules/opensearch/opensearchLoggingDisabled.js';
import { rdsBackupRetentionLow } from './rules/rds/rdsBackupRetentionLow.js';
import { rdsDeletionProtectionDisabled } from './rules/rds/rdsDeletionProtectionDisabled.js';
import { rdsEncryptionDisabled } from './rules/rds/rdsEncryptionDisabled.js';
import { rdsManagedSecretWithoutCmk } from './rules/rds/rdsManagedSecretWithoutCmk.js';
import { rdsPubliclyAccessible } from './rules/rds/rdsPubliclyAccessible.js';
import { redshiftAuditLoggingDisabled } from './rules/redshift/redshiftAuditLoggingDisabled.js';
import { redshiftEncryptionDisabled } from './rules/redshift/redshiftEncryptionDisabled.js';
import { redshiftPubliclyAccessible } from './rules/redshift/redshiftPubliclyAccessible.js';
import { route53DnssecDisabled } from './rules/route53/route53DnssecDisabled.js';
import { route53HealthCheckSuboptimal } from './rules/route53/route53HealthCheckSuboptimal.js';
import { route53QueryLoggingDisabled } from './rules/route53/route53QueryLoggingDisabled.js';
import { s3BucketAccessLoggingDisabled } from './rules/s3/s3BucketAccessLoggingDisabled.js';
import { s3BucketPolicyNonSsl } from './rules/s3/s3BucketPolicyNonSsl.js';
import { s3BucketPolicySelfLockout } from './rules/s3/s3BucketPolicySelfLockout.js';
import { s3BucketPublicAccess } from './rules/s3/s3BucketPublicAccess.js';
import { s3BucketVersioningDisabled } from './rules/s3/s3BucketVersioningDisabled.js';
import { s3ReplicationMissing } from './rules/s3/s3ReplicationMissing.js';
import { secretsManagerSecretPublic } from './rules/secretsmanager/secretsManagerSecretPublic.js';
import { snsEncryptionDisabled } from './rules/sns/snsEncryptionDisabled.js';
import { snsTopicPolicySelfLockout } from './rules/sns/snsTopicPolicySelfLockout.js';
import { sqsEncryptionDisabled } from './rules/sqs/sqsEncryptionDisabled.js';
import { sqsQueueNoDlq } from './rules/sqs/sqsQueueNoDlq.js';
import { sqsQueuePolicySelfLockout } from './rules/sqs/sqsQueuePolicySelfLockout.js';
import { vpcDefaultSecurityGroupRulesPresent } from './rules/vpc/vpcDefaultSecurityGroupRulesPresent.js';
import { vpcFlowLogsMissing } from './rules/vpc/vpcFlowLogsMissing.js';
import { wafLoggingDisabled } from './rules/waf/wafLoggingDisabled.js';
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
  lambdaDlqMissing,
  lambdaReservedConcurrencyMissing,
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
  s3ReplicationMissing,
  // RDS
  rdsEncryptionDisabled,
  rdsPubliclyAccessible,
  rdsManagedSecretWithoutCmk,
  rdsBackupRetentionLow,
  rdsDeletionProtectionDisabled,
  // IAM
  iamPoliciesOverlyPermissive,
  iamUserDirectPolicies,
  iamCrossAccountTrust,
  iamPermissionBoundaryMissing,
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
  eventbridgeRuleNoTargets,
  eventbridgeTargetDlqMissing,
  // Redshift
  redshiftPubliclyAccessible,
  redshiftEncryptionDisabled,
  redshiftAuditLoggingDisabled,
  // Kinesis / EFS / ElastiCache
  kinesisEncryptionDisabled,
  kinesisRetentionMinimum,
  efsEncryptionDisabled,
  elasticacheEncryptionDisabled,
  elasticacheAuthTokenMissing,
  elasticacheFailoverDisabled,
  // VPC
  vpcFlowLogsMissing,
  vpcDefaultSecurityGroupRulesPresent,
  // WAF
  wafWebAclMisconfigured,
  wafLoggingDisabled,
  // CloudFront / CloudTrail
  cloudfrontHttpsOnly,
  cloudfrontTlsOutdated,
  cloudfrontLoggingDisabled,
  cloudfrontWafMissing,
  cloudtrailLoggingDisabled,
  // Cognito
  cognitoPasswordPolicyWeak,
  cognitoMfaDisabled,
  cognitoAdvancedSecurityDisabled,
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
  elbDeletionProtectionDisabled,
  // MSK
  mskClientAuthenticationMissing,
  mskEncryptionWeak,
  // OpenSearch
  opensearchEncryptionDisabled,
  opensearchAccessControlWeak,
  opensearchLoggingDisabled,
  // AutoScaling
  autoscalingLaunchConfigPublicIp,
  autoscalingGroupNoElbHealthcheck,
  // AppSync
  appsyncApiKeyAuth,
  appsyncWafMissing,
  // ACM / Backup / CloudWatch / Glue / Route53
  acmCertificateEmailValidation,
  backupVaultHardening,
  backupPlanMisconfigured,
  cloudwatchLogsEncryptionDisabled,
  glueConnectionNetworkIsolation,
  glueJobEncryptionMissing,
  route53DnssecDisabled,
  route53QueryLoggingDisabled,
  route53HealthCheckSuboptimal,
  // DynamoDB
  dynamodbDeletionProtectionDisabled,
  dynamodbEncryptionAwsOwnedKey,
  dynamodbPitrDisabled,
  // ECS
  ecsContainerPrivileged,
  ecsSecretsPlaintext,
  ecsServiceConnectAccessLogsMissing,
  ecsResourcesMissing,
  // SQS
  sqsQueueNoDlq,
  sqsEncryptionDisabled,
  sqsQueuePolicySelfLockout,
  // API Gateway
  apigatewayMethodAuthMissing,
  apigatewayDefaultEndpointEnabled,
  apigatewayThrottlingMissing,
];
