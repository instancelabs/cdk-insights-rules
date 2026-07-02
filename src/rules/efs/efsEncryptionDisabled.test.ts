import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { efsEncryptionDisabled } from './efsEncryptionDisabled';

const fileSystem = (properties: object): CfnTemplate => ({
  Resources: {
    Fs: { Type: 'AWS::EFS::FileSystem', Properties: properties },
  },
});

describe('efs-encryption-disabled', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [efsEncryptionDisabled]);

  it('flags an unencrypted file system (absent or false)', () => {
    expect(run(fileSystem({}))).toHaveLength(1);
    expect(run(fileSystem({ Encrypted: false }))).toHaveLength(1);
  });

  it('does not flag encrypted file systems or intrinsic values', () => {
    expect(run(fileSystem({ Encrypted: true }))).toHaveLength(0);
    expect(run(fileSystem({ Encrypted: 'true' }))).toHaveLength(0);
    expect(
      run(fileSystem({ Encrypted: { 'Fn::If': ['X', true, false] } }))
    ).toHaveLength(0);
  });
});
