import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { lambdaPermissionScopedWildcard } from './lambdaPermissionScopedWildcard';

describe('lambda-permission-scoped-wildcard', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [lambdaPermissionScopedWildcard]);

  const permission = (rtype: string, properties: object): CfnTemplate => ({
    Resources: {
      Perm: {
        Type: rtype,
        Properties: { Action: 'lambda:InvokeFunction', ...properties },
      },
    },
  });

  it('flags a wildcard principal scoped by a source restriction', () => {
    expect(
      run(
        permission('AWS::Lambda::Permission', {
          Principal: '*',
          PrincipalOrgID: 'o-abc123',
        })
      )
    ).toHaveLength(1);
    expect(
      run(
        permission('AWS::Lambda::Permission', {
          Principal: '*',
          SourceAccount: '111122223333',
        })
      )
    ).toHaveLength(1);
  });

  it('does not flag org-shared layers, unscoped wildcards, or named principals', () => {
    expect(
      run(
        permission('AWS::Lambda::LayerVersionPermission', {
          Principal: '*',
          OrganizationId: 'o-abc123',
        })
      )
    ).toHaveLength(0);
    // Unscoped wildcard is lambda-permission-public's territory.
    expect(
      run(permission('AWS::Lambda::Permission', { Principal: '*' }))
    ).toHaveLength(0);
    expect(
      run(
        permission('AWS::Lambda::Permission', {
          Principal: '111122223333',
          SourceAccount: '111122223333',
        })
      )
    ).toHaveLength(0);
  });
});
