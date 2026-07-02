import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { opensearchLoggingDisabled } from './opensearchLoggingDisabled';

describe('opensearch-logging-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [opensearchLoggingDisabled]);

  const domain = (options?: object): CfnTemplate => ({
    Resources: {
      Domain: {
        Type: 'AWS::OpenSearchService::Domain',
        Properties: options ? { LogPublishingOptions: options } : {},
      },
    },
  });

  it('flags a domain with no logging (two findings)', () => {
    expect(run(domain())).toHaveLength(2);
  });

  it('does not flag audit and application logging enabled', () => {
    expect(
      run(
        domain({
          AUDIT_LOGS: { Enabled: true },
          ES_APPLICATION_LOGS: { Enabled: true },
        })
      )
    ).toHaveLength(0);
  });
});
