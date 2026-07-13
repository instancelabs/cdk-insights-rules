import { acmCertificateEmailValidation } from './rules/acm/acmCertificateEmailValidation.js';
import { apigatewayDefaultEndpointEnabled } from './rules/apigateway/apigatewayDefaultEndpointEnabled.js';
import { apigatewayMethodAuthMissing } from './rules/apigateway/apigatewayMethodAuthMissing.js';
import { apigatewayStageLoggingDisabled } from './rules/apigateway/apigatewayStageLoggingDisabled.js';
import { apigatewayThrottlingMissing } from './rules/apigateway/apigatewayThrottlingMissing.js';
import { appsyncApiKeyAuth } from './rules/appsync/appsyncApiKeyAuth.js';
import { appsyncLoggingDisabled } from './rules/appsync/appsyncLoggingDisabled.js';
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
import { cloudwatchAlarmActionsMissing } from './rules/cloudwatch/cloudwatchAlarmActionsMissing.js';
import { cloudwatchLogsEncryptionDisabled } from './rules/cloudwatch/cloudwatchLogsEncryptionDisabled.js';
import { cloudwatchLogsRetentionMissing } from './rules/cloudwatch/cloudwatchLogsRetentionMissing.js';
import { cognitoAdvancedSecurityDisabled } from './rules/cognito/cognitoAdvancedSecurityDisabled.js';
import { cognitoMfaDisabled } from './rules/cognito/cognitoMfaDisabled.js';
import { cognitoPasswordPolicyWeak } from './rules/cognito/cognitoPasswordPolicyWeak.js';
import { dynamodbAutoscalingMissing } from './rules/dynamodb/dynamodbAutoscalingMissing.js';
import { dynamodbDeletionProtectionDisabled } from './rules/dynamodb/dynamodbDeletionProtectionDisabled.js';
import { dynamodbEncryptionAwsOwnedKey } from './rules/dynamodb/dynamodbEncryptionAwsOwnedKey.js';
import { dynamodbPitrDisabled } from './rules/dynamodb/dynamodbPitrDisabled.js';
import { dynamodbStreamsDisabled } from './rules/dynamodb/dynamodbStreamsDisabled.js';
import { ebsVolumeGp2Storage } from './rules/ec2/ebsVolumeGp2Storage.js';
import { ebsVolumeUnencrypted } from './rules/ec2/ebsVolumeUnencrypted.js';
import { ec2Imdsv2NotEnforced } from './rules/ec2/ec2Imdsv2NotEnforced.js';
import { ec2InstancePublicIp } from './rules/ec2/ec2InstancePublicIp.js';
import { ec2InstanceTypeOutdated } from './rules/ec2/ec2InstanceTypeOutdated.js';
import { ec2SubnetAutoPublicIp } from './rules/ec2/ec2SubnetAutoPublicIp.js';
import { natGatewayUsage } from './rules/ec2/natGatewayUsage.js';
import { securityGroupNoRules } from './rules/ec2/securityGroupNoRules.js';
import { securityGroupUnrestrictedEgress } from './rules/ec2/securityGroupUnrestrictedEgress.js';
import { securityGroupUnrestrictedIngress } from './rules/ec2/securityGroupUnrestrictedIngress.js';
import { ecrLifecyclePolicyMissing } from './rules/ecr/ecrLifecyclePolicyMissing.js';
import { ecrMutableTags } from './rules/ecr/ecrMutableTags.js';
import { ecrScanOnPushDisabled } from './rules/ecr/ecrScanOnPushDisabled.js';
import { ecsContainerPrivileged } from './rules/ecs/ecsContainerPrivileged.js';
import { ecsDeploymentCircuitBreakerDisabled } from './rules/ecs/ecsDeploymentCircuitBreakerDisabled.js';
import { ecsLoggingDisabled } from './rules/ecs/ecsLoggingDisabled.js';
import { ecsResourcesMissing } from './rules/ecs/ecsResourcesMissing.js';
import { ecsSecretsPlaintext } from './rules/ecs/ecsSecretsPlaintext.js';
import { ecsServiceConnectAccessLogsMissing } from './rules/ecs/ecsServiceConnectAccessLogsMissing.js';
import { ecsTaskDefinitionMutableImageTag } from './rules/ecs/ecsTaskDefinitionMutableImageTag.js';
import { efsEncryptionDisabled } from './rules/efs/efsEncryptionDisabled.js';
import { eksControlPlaneLoggingDisabled } from './rules/eks/eksControlPlaneLoggingDisabled.js';
import { eksPrivateEndpointAccessDisabled } from './rules/eks/eksPrivateEndpointAccessDisabled.js';
import { eksPublicEndpointUnrestricted } from './rules/eks/eksPublicEndpointUnrestricted.js';
import { eksSecretsEncryptionDisabled } from './rules/eks/eksSecretsEncryptionDisabled.js';
import { elasticacheAuthTokenMissing } from './rules/elasticache/elasticacheAuthTokenMissing.js';
import { elasticacheEncryptionDisabled } from './rules/elasticache/elasticacheEncryptionDisabled.js';
import { elasticacheFailoverDisabled } from './rules/elasticache/elasticacheFailoverDisabled.js';
import { elbDeletionProtectionDisabled } from './rules/elb/elbDeletionProtectionDisabled.js';
import { elbHttpsListenersMissing } from './rules/elb/elbHttpsListenersMissing.js';
import { elbLoggingDisabled } from './rules/elb/elbLoggingDisabled.js';
import { elbSecurityPolicyOutdated } from './rules/elb/elbSecurityPolicyOutdated.js';
import { eventbridgeBusPolicyWildcardPrincipal } from './rules/eventbridge/eventbridgeBusPolicyWildcardPrincipal.js';
import { eventbridgeRuleDisabled } from './rules/eventbridge/eventbridgeRuleDisabled.js';
import { eventbridgeRuleNoTargets } from './rules/eventbridge/eventbridgeRuleNoTargets.js';
import { eventbridgeTargetDlqMissing } from './rules/eventbridge/eventbridgeTargetDlqMissing.js';
import { glueConnectionNetworkIsolation } from './rules/glue/glueConnectionNetworkIsolation.js';
import { glueJobEncryptionMissing } from './rules/glue/glueJobEncryptionMissing.js';
import { iamCrossAccountTrust } from './rules/iam/iamCrossAccountTrust.js';
import { iamPermissionBoundaryMissing } from './rules/iam/iamPermissionBoundaryMissing.js';
import { iamPoliciesOverlyPermissive } from './rules/iam/iamPoliciesOverlyPermissive.js';
import { iamRoleAnonymousAssume } from './rules/iam/iamRoleAnonymousAssume.js';
import { iamUserDirectPolicies } from './rules/iam/iamUserDirectPolicies.js';
import { imagebuilderAmiPublicLaunchPermission } from './rules/imagebuilder/imagebuilderAmiPublicLaunchPermission.js';
import { kinesisEncryptionDisabled } from './rules/kinesis/kinesisEncryptionDisabled.js';
import { kinesisRetentionMinimum } from './rules/kinesis/kinesisRetentionMinimum.js';
import { kmsKeyPolicyPublic } from './rules/kms/kmsKeyPolicyPublic.js';
import { kmsKeyPolicySelfLockout } from './rules/kms/kmsKeyPolicySelfLockout.js';
import { lambdaDlqMissing } from './rules/lambda/lambdaDlqMissing.js';
import { lambdaEnvSensitiveData } from './rules/lambda/lambdaEnvSensitiveData.js';
import { lambdaMemoryOptimization } from './rules/lambda/lambdaMemoryOptimization.js';
import { lambdaPermissionPublic } from './rules/lambda/lambdaPermissionPublic.js';
import { lambdaPermissionScopedWildcard } from './rules/lambda/lambdaPermissionScopedWildcard.js';
import { lambdaPermissionServiceUnrestricted } from './rules/lambda/lambdaPermissionServiceUnrestricted.js';
import { lambdaReservedConcurrencyMissing } from './rules/lambda/lambdaReservedConcurrencyMissing.js';
import { lambdaRuntimeDeprecated } from './rules/lambda/lambdaRuntimeDeprecated.js';
import { lambdaTracingDisabled } from './rules/lambda/lambdaTracingDisabled.js';
import { lambdaUrlAuthNone } from './rules/lambda/lambdaUrlAuthNone.js';
import { lambdaVpcNatCost } from './rules/lambda/lambdaVpcNatCost.js';
import { mskBrokerLoggingDisabled } from './rules/msk/mskBrokerLoggingDisabled.js';
import { mskClientAuthenticationMissing } from './rules/msk/mskClientAuthenticationMissing.js';
import { mskDataVolumeCmkMissing } from './rules/msk/mskDataVolumeCmkMissing.js';
import { mskEncryptionWeak } from './rules/msk/mskEncryptionWeak.js';
import { opensearchAccessControlWeak } from './rules/opensearch/opensearchAccessControlWeak.js';
import { opensearchEncryptionDisabled } from './rules/opensearch/opensearchEncryptionDisabled.js';
import { opensearchLoggingDisabled } from './rules/opensearch/opensearchLoggingDisabled.js';
import { rdsBackupRetentionLow } from './rules/rds/rdsBackupRetentionLow.js';
import { rdsDeletionProtectionDisabled } from './rules/rds/rdsDeletionProtectionDisabled.js';
import { rdsEncryptionDisabled } from './rules/rds/rdsEncryptionDisabled.js';
import { rdsEnhancedMonitoringDisabled } from './rules/rds/rdsEnhancedMonitoringDisabled.js';
import { rdsLoggingDisabled } from './rules/rds/rdsLoggingDisabled.js';
import { rdsManagedSecretWithoutCmk } from './rules/rds/rdsManagedSecretWithoutCmk.js';
import { rdsMasterPasswordPlaintext } from './rules/rds/rdsMasterPasswordPlaintext.js';
import { rdsMultiAzGp2Storage } from './rules/rds/rdsMultiAzGp2Storage.js';
import { rdsPubliclyAccessible } from './rules/rds/rdsPubliclyAccessible.js';
import { redshiftAuditLoggingDisabled } from './rules/redshift/redshiftAuditLoggingDisabled.js';
import { redshiftEncryptionDisabled } from './rules/redshift/redshiftEncryptionDisabled.js';
import { redshiftPubliclyAccessible } from './rules/redshift/redshiftPubliclyAccessible.js';
import { route53DnssecDisabled } from './rules/route53/route53DnssecDisabled.js';
import { route53HealthCheckSuboptimal } from './rules/route53/route53HealthCheckSuboptimal.js';
import { route53QueryLoggingDisabled } from './rules/route53/route53QueryLoggingDisabled.js';
import { s3BucketAccessLoggingDisabled } from './rules/s3/s3BucketAccessLoggingDisabled.js';
import { s3BucketEncryptionAwsManaged } from './rules/s3/s3BucketEncryptionAwsManaged.js';
import { s3BucketPolicyNonSsl } from './rules/s3/s3BucketPolicyNonSsl.js';
import { s3BucketPolicyPublicRead } from './rules/s3/s3BucketPolicyPublicRead.js';
import { s3BucketPolicySelfLockout } from './rules/s3/s3BucketPolicySelfLockout.js';
import { s3BucketPublicAccess } from './rules/s3/s3BucketPublicAccess.js';
import { s3BucketVersioningDisabled } from './rules/s3/s3BucketVersioningDisabled.js';
import { s3IntelligentTiering } from './rules/s3/s3IntelligentTiering.js';
import { s3LifecyclePolicyMissing } from './rules/s3/s3LifecyclePolicyMissing.js';
import { s3ReplicationMissing } from './rules/s3/s3ReplicationMissing.js';
import { secretsManagerRotationMissing } from './rules/secretsmanager/secretsManagerRotationMissing.js';
import { secretsManagerSecretPublic } from './rules/secretsmanager/secretsManagerSecretPublic.js';
import { snsEncryptionDisabled } from './rules/sns/snsEncryptionDisabled.js';
import { snsTopicPolicySelfLockout } from './rules/sns/snsTopicPolicySelfLockout.js';
import { sqsEncryptionDisabled } from './rules/sqs/sqsEncryptionDisabled.js';
import { sqsQueueNoDlq } from './rules/sqs/sqsQueueNoDlq.js';
import { sqsQueuePolicySelfLockout } from './rules/sqs/sqsQueuePolicySelfLockout.js';
import { stepfunctionsLoggingDisabled } from './rules/stepfunctions/stepfunctionsLoggingDisabled.js';
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
  lambdaPermissionScopedWildcard,
  lambdaRuntimeDeprecated,
  lambdaEnvSensitiveData,
  lambdaDlqMissing,
  lambdaReservedConcurrencyMissing,
  lambdaMemoryOptimization,
  lambdaVpcNatCost,
  lambdaTracingDisabled,
  // EC2 / EBS
  ec2Imdsv2NotEnforced,
  ec2InstancePublicIp,
  ec2SubnetAutoPublicIp,
  ec2InstanceTypeOutdated,
  natGatewayUsage,
  ebsVolumeUnencrypted,
  ebsVolumeGp2Storage,
  securityGroupUnrestrictedIngress,
  securityGroupUnrestrictedEgress,
  securityGroupNoRules,
  // S3
  s3BucketPublicAccess,
  s3BucketEncryptionAwsManaged,
  s3BucketVersioningDisabled,
  s3BucketPolicySelfLockout,
  s3BucketPolicyNonSsl,
  s3BucketPolicyPublicRead,
  s3BucketAccessLoggingDisabled,
  s3ReplicationMissing,
  s3LifecyclePolicyMissing,
  s3IntelligentTiering,
  // RDS
  rdsEncryptionDisabled,
  rdsMasterPasswordPlaintext,
  rdsPubliclyAccessible,
  rdsManagedSecretWithoutCmk,
  rdsBackupRetentionLow,
  rdsDeletionProtectionDisabled,
  rdsMultiAzGp2Storage,
  rdsEnhancedMonitoringDisabled,
  rdsLoggingDisabled,
  // IAM
  iamPoliciesOverlyPermissive,
  iamUserDirectPolicies,
  iamCrossAccountTrust,
  iamRoleAnonymousAssume,
  iamPermissionBoundaryMissing,
  // KMS
  kmsKeyPolicyPublic,
  kmsKeyPolicySelfLockout,
  // Secrets Manager
  secretsManagerSecretPublic,
  secretsManagerRotationMissing,
  // Image Builder
  imagebuilderAmiPublicLaunchPermission,
  // SNS
  snsEncryptionDisabled,
  snsTopicPolicySelfLockout,
  // EventBridge
  eventbridgeBusPolicyWildcardPrincipal,
  eventbridgeRuleNoTargets,
  eventbridgeRuleDisabled,
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
  ecrLifecyclePolicyMissing,
  // EKS
  eksPublicEndpointUnrestricted,
  eksPrivateEndpointAccessDisabled,
  eksSecretsEncryptionDisabled,
  eksControlPlaneLoggingDisabled,
  // ELB
  elbHttpsListenersMissing,
  elbLoggingDisabled,
  elbDeletionProtectionDisabled,
  elbSecurityPolicyOutdated,
  // MSK
  mskClientAuthenticationMissing,
  mskEncryptionWeak,
  mskDataVolumeCmkMissing,
  mskBrokerLoggingDisabled,
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
  appsyncLoggingDisabled,
  // ACM / Backup / CloudWatch / Glue / Route53
  acmCertificateEmailValidation,
  backupVaultHardening,
  backupPlanMisconfigured,
  cloudwatchLogsEncryptionDisabled,
  cloudwatchLogsRetentionMissing,
  cloudwatchAlarmActionsMissing,
  glueConnectionNetworkIsolation,
  glueJobEncryptionMissing,
  route53DnssecDisabled,
  route53QueryLoggingDisabled,
  route53HealthCheckSuboptimal,
  // Step Functions
  stepfunctionsLoggingDisabled,
  // DynamoDB
  dynamodbDeletionProtectionDisabled,
  dynamodbEncryptionAwsOwnedKey,
  dynamodbPitrDisabled,
  dynamodbAutoscalingMissing,
  dynamodbStreamsDisabled,
  // ECS
  ecsContainerPrivileged,
  ecsSecretsPlaintext,
  ecsServiceConnectAccessLogsMissing,
  ecsResourcesMissing,
  ecsDeploymentCircuitBreakerDisabled,
  ecsLoggingDisabled,
  ecsTaskDefinitionMutableImageTag,
  // SQS
  sqsQueueNoDlq,
  sqsEncryptionDisabled,
  sqsQueuePolicySelfLockout,
  // API Gateway
  apigatewayMethodAuthMissing,
  apigatewayStageLoggingDisabled,
  apigatewayDefaultEndpointEnabled,
  apigatewayThrottlingMissing,
];
