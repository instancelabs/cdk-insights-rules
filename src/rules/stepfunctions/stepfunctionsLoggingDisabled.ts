import type { Rule } from '../../types';

/**
 * stepfunctions-logging-disabled
 *
 * A state machine without logging leaves execution failures reconstructable
 * only from the (90-day) execution history UI.
 */
export const stepfunctionsLoggingDisabled: Rule = {
  metadata: {
    ruleId: 'stepfunctions-logging-disabled',
    name: 'Step Functions Logging Disabled',
    description:
      'Detects Step Functions state machines without a logging configuration.',
    severity: 'MEDIUM',
    wafPillar: 'Operational Excellence',
    resourceTypes: ['AWS::StepFunctions::StateMachine'],
    awsDocUrl:
      'https://docs.aws.amazon.com/step-functions/latest/dg/cw-logs.html',
    remediationSteps: [
      'Set LoggingConfiguration with Level ALL or ERROR and a CloudWatch log group destination',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::StepFunctions::StateMachine') {
        continue;
      }
      const level = resource.Properties?.LoggingConfiguration?.Level;
      if (level === undefined || level === 'OFF') {
        report(resourceId, {
          issue: 'Step Functions state machine lacks logging configuration.',
          recommendation:
            'Enable LoggingConfiguration (Level ERROR or ALL) so execution failures are captured in CloudWatch Logs.',
        });
      }
    }
  },

  example: {
    flagged: `import * as stepfunctions from 'aws-cdk-lib/aws-stepfunctions';

new stepfunctions.CfnStateMachine(this, 'StateMachine', {
  roleArn: 'arn:aws:iam::111122223333:role/sfn-role',
  definitionString: '{"StartAt":"Done","States":{"Done":{"Type":"Succeed"}}}',
});`,
    fixed: `import * as stepfunctions from 'aws-cdk-lib/aws-stepfunctions';

new stepfunctions.CfnStateMachine(this, 'StateMachine', {
  roleArn: 'arn:aws:iam::111122223333:role/sfn-role',
  definitionString: '{"StartAt":"Done","States":{"Done":{"Type":"Succeed"}}}',
  loggingConfiguration: {
    level: 'ERROR',
    destinations: [
      {
        cloudWatchLogsLogGroup: {
          logGroupArn:
            'arn:aws:logs:eu-west-2:111122223333:log-group:/sfn/app',
        },
      },
    ],
  },
});`,
  },
};
