import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { s3IntelligentTiering } from './s3IntelligentTiering';

describe('s3-intelligent-tiering', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [s3IntelligentTiering]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::S3::Bucket', Properties: { ...properties } },
    },
  });

  it('flags a bucket without intelligent tiering', () => {
    expect(run(res({}))).toHaveLength(1);
  });

  it('recognizes an IT lifecycle transition or an IT configuration', () => {
    expect(
      run(
        res({
          LifecycleConfiguration: {
            Rules: [
              {
                Status: 'Enabled',
                Transitions: [{ StorageClass: 'INTELLIGENT_TIERING' }],
              },
            ],
          },
        })
      )
    ).toHaveLength(0);
    expect(
      run(res({ IntelligentTieringConfigurations: [{ Id: 't' }] }))
    ).toHaveLength(0);
  });
});
