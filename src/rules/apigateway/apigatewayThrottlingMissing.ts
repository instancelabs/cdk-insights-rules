import type { CfnResource, Rule } from '../../types';

/** True when a usage-plan throttle object sets a rate or burst limit. */
const hasThrottleLimits = (throttle: unknown): boolean =>
  !!throttle &&
  typeof throttle === 'object' &&
  ((throttle as Record<string, unknown>).RateLimit !== undefined ||
    (throttle as Record<string, unknown>).BurstLimit !== undefined);

/**
 * Collect the stages a usage plan throttles. A plan covers a stage when the
 * plan sets a top-level Throttle, or the ApiStage entry sets its own Throttle
 * (method-level throttle map). Stages are identified by `{ Ref: id }` logical
 * id or by literal stage name.
 */
const collectThrottledStages = (
  resources: [string, CfnResource][]
): { ids: Set<string>; names: Set<string> } => {
  const ids = new Set<string>();
  const names = new Set<string>();
  for (const [, resource] of resources) {
    if (resource.Type !== 'AWS::ApiGateway::UsagePlan') {
      continue;
    }
    const planThrottled = hasThrottleLimits(resource.Properties?.Throttle);
    const apiStages = resource.Properties?.ApiStages;
    if (!Array.isArray(apiStages)) {
      continue;
    }
    for (const apiStage of apiStages) {
      const stageThrottle = apiStage?.Throttle;
      const stageThrottled =
        planThrottled ||
        (!!stageThrottle &&
          typeof stageThrottle === 'object' &&
          Object.values(stageThrottle).some(hasThrottleLimits));
      if (!stageThrottled) {
        continue;
      }
      const stage = apiStage?.Stage;
      if (typeof stage === 'string') {
        names.add(stage);
      } else if (stage && typeof stage === 'object') {
        const ref = (stage as Record<string, unknown>).Ref;
        if (typeof ref === 'string') {
          ids.add(ref);
        }
      }
    }
  }
  return { ids, names };
};

/**
 * apigateway-throttling-missing — API Gateway stage with no throttling at all.
 *
 * A stage that sets no rate or burst limits leaves its backend integrations
 * exposed to traffic spikes and uncontrolled cost. A stage counts as throttled
 * when its own MethodSettings set a ThrottlingRateLimit / ThrottlingBurstLimit,
 * or when a usage plan in the template attaches throttle limits to it — both
 * are legitimate ways to throttle, so neither is flagged.
 */
export const apigatewayThrottlingMissing: Rule = {
  metadata: {
    ruleId: 'apigateway-throttling-missing',
    name: 'API Gateway Stage Missing Throttling',
    description:
      'Detects API Gateway stages with no rate or burst limits from either MethodSettings or a usage plan, leaving backends exposed to traffic spikes and uncontrolled cost.',
    severity: 'LOW',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::ApiGateway::Stage'],
    awsDocUrl:
      'https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html',
    remediationSteps: [
      'Add MethodSettings with ThrottlingRateLimit and ThrottlingBurstLimit (e.g. for HttpMethod "*")',
      'Or attach the stage to a usage plan with throttle limits',
      'Tune per-method limits for hot paths',
    ],
    complianceFrameworks: ['SOC2'],
  },

  check: (template, report) => {
    const resources = Object.entries(template.Resources ?? {});
    const throttledViaUsagePlan = collectThrottledStages(resources);

    for (const [resourceId, resource] of resources) {
      if (resource.Type !== 'AWS::ApiGateway::Stage') {
        continue;
      }

      const methodSettings = resource.Properties?.MethodSettings;
      const hasOwnThrottling =
        Array.isArray(methodSettings) &&
        methodSettings.some(
          (setting) =>
            setting?.ThrottlingBurstLimit !== undefined ||
            setting?.ThrottlingRateLimit !== undefined
        );

      const stageName = resource.Properties?.StageName;
      const coveredByUsagePlan =
        throttledViaUsagePlan.ids.has(resourceId) ||
        (typeof stageName === 'string' &&
          throttledViaUsagePlan.names.has(stageName));

      if (!hasOwnThrottling && !coveredByUsagePlan) {
        report(resourceId, {
          issue:
            'API Gateway stage does not configure request throttling (no method-level limits and no usage plan with throttle limits).',
          recommendation:
            'Add MethodSettings with ThrottlingRateLimit and ThrottlingBurstLimit (e.g. for HttpMethod "*"), or attach the stage to a usage plan with throttle limits, to protect backend integrations from traffic spikes and control cost.',
        });
      }
    }
  },

  example: {
    flagged: `import * as apigateway from 'aws-cdk-lib/aws-apigateway';

new apigateway.CfnStage(this, 'Stage', {
  restApiId: 'abc123',
  deploymentId: 'dep123',
  stageName: 'prod',
});`,
    fixed: `import * as apigateway from 'aws-cdk-lib/aws-apigateway';

new apigateway.CfnStage(this, 'Stage', {
  restApiId: 'abc123',
  deploymentId: 'dep123',
  stageName: 'prod',
  methodSettings: [
    {
      httpMethod: '*',
      resourcePath: '/*',
      throttlingRateLimit: 100,
      throttlingBurstLimit: 200,
    },
  ],
});`,
  },
};
