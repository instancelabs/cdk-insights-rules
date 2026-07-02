import type { Rule } from '../../types';

const isNonEmptyArray = (value: unknown): boolean =>
  Array.isArray(value) && value.length > 0;

/**
 * autoscaling-group-no-elb-healthcheck
 *
 * An ASG behind a load balancer with the default EC2 health check only
 * recycles instances on hardware failure — an app that hangs but keeps its
 * instance healthy stays in service. ELB health checks close that gap.
 */
export const autoscalingGroupNoElbHealthcheck: Rule = {
  metadata: {
    ruleId: 'autoscaling-group-no-elb-healthcheck',
    name: 'AutoScaling Group Without ELB Health Check',
    description:
      'Detects AutoScaling groups attached to a load balancer that do not use ELB health checks.',
    severity: 'MEDIUM',
    wafPillar: 'Reliability',
    resourceTypes: ['AWS::AutoScaling::AutoScalingGroup'],
    awsDocUrl:
      'https://docs.aws.amazon.com/autoscaling/ec2/userguide/healthcheck.html',
    remediationSteps: [
      'Set HealthCheckType to ELB (with a HealthCheckGracePeriod) so app-level failures detected by the load balancer recycle the instance',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::AutoScaling::AutoScalingGroup') {
        continue;
      }
      const props = resource.Properties ?? {};
      const attachedToLb =
        isNonEmptyArray(props.LoadBalancerNames) ||
        isNonEmptyArray(props.TargetGroupARNs);
      if (attachedToLb && props.HealthCheckType !== 'ELB') {
        report(resourceId, {
          issue:
            'AutoScaling group attached to a load balancer is not using ELB health checks.',
          recommendation:
            'Set HealthCheckType to ELB so instances failing app-level health checks are replaced, not just hardware failures.',
        });
      }
    }
  },

  example: {
    flagged: `import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';

new autoscaling.CfnAutoScalingGroup(this, 'Asg', {
  minSize: '1',
  maxSize: '3',
  targetGroupArns: [
    'arn:aws:elasticloadbalancing:eu-west-2:111122223333:targetgroup/app/abc',
  ],
});`,
    fixed: `import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';

new autoscaling.CfnAutoScalingGroup(this, 'Asg', {
  minSize: '1',
  maxSize: '3',
  targetGroupArns: [
    'arn:aws:elasticloadbalancing:eu-west-2:111122223333:targetgroup/app/abc',
  ],
  healthCheckType: 'ELB',
  healthCheckGracePeriod: 300,
});`,
  },
};
