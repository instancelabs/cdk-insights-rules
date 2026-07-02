import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { ecrScanOnPushDisabled } from './ecrScanOnPushDisabled';

const repo = (properties: object): CfnTemplate => ({
  Resources: {
    Repo: { Type: 'AWS::ECR::Repository', Properties: properties },
  },
});

describe('ecr-scan-on-push-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [ecrScanOnPushDisabled]);

  it('flags a repository without scan-on-push (absent or false)', () => {
    expect(run(repo({}))).toHaveLength(1);
    expect(
      run(repo({ ImageScanningConfiguration: { ScanOnPush: false } }))
    ).toHaveLength(1);
  });

  it('does not flag scan-on-push enabled or intrinsic values', () => {
    expect(
      run(repo({ ImageScanningConfiguration: { ScanOnPush: true } }))
    ).toHaveLength(0);
    expect(
      run(repo({ ImageScanningConfiguration: { ScanOnPush: 'true' } }))
    ).toHaveLength(0);
    expect(
      run(
        repo({
          ImageScanningConfiguration: {
            ScanOnPush: { 'Fn::If': ['X', true, false] },
          },
        })
      )
    ).toHaveLength(0);
  });
});
