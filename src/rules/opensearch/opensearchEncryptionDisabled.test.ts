import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { opensearchEncryptionDisabled } from './opensearchEncryptionDisabled';

describe('opensearch-encryption-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [opensearchEncryptionDisabled]);

  it('flags a domain missing both encryption settings (two findings)', () => {
    expect(
      run({
        Resources: {
          Domain: { Type: 'AWS::OpenSearchService::Domain', Properties: {} },
        },
      })
    ).toHaveLength(2);
  });

  it('covers the legacy Elasticsearch type', () => {
    expect(
      run({
        Resources: {
          Domain: { Type: 'AWS::Elasticsearch::Domain', Properties: {} },
        },
      })
    ).toHaveLength(2);
  });

  it('does not flag a fully encrypted domain', () => {
    expect(
      run({
        Resources: {
          Domain: {
            Type: 'AWS::OpenSearchService::Domain',
            Properties: {
              EncryptionAtRestOptions: { Enabled: true },
              NodeToNodeEncryptionOptions: { Enabled: true },
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
