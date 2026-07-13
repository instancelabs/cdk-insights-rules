import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { secretsManagerRotationMissing } from './secretsManagerRotationMissing';

describe('secrets-manager-rotation-missing', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [secretsManagerRotationMissing]);

  it('flags a secret with no rotation schedule', () => {
    const findings = run({
      Resources: { Secret: { Type: 'AWS::SecretsManager::Secret' } },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].resourceId).toBe('Secret');
  });

  it('does not flag a secret targeted by a rotation schedule', () => {
    expect(
      run({
        Resources: {
          Secret: { Type: 'AWS::SecretsManager::Secret' },
          Rotation: {
            Type: 'AWS::SecretsManager::RotationSchedule',
            Properties: {
              SecretId: { Ref: 'Secret' },
              RotationRules: { AutomaticallyAfterDays: 30 },
            },
          },
        },
      })
    ).toHaveLength(0);
  });

  it('flags only the unrotated secret when several exist', () => {
    const findings = run({
      Resources: {
        Rotated: { Type: 'AWS::SecretsManager::Secret' },
        Static: { Type: 'AWS::SecretsManager::Secret' },
        Rotation: {
          Type: 'AWS::SecretsManager::RotationSchedule',
          Properties: { SecretId: { Ref: 'Rotated' } },
        },
      },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].resourceId).toBe('Static');
  });

  it('stands down entirely when a schedule target is unresolvable', () => {
    expect(
      run({
        Resources: {
          Secret: { Type: 'AWS::SecretsManager::Secret' },
          Rotation: {
            Type: 'AWS::SecretsManager::RotationSchedule',
            Properties: {
              SecretId:
                'arn:aws:secretsmanager:eu-west-2:111122223333:secret:external',
            },
          },
        },
      })
    ).toHaveLength(0);
  });
});
