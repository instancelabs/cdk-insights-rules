import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { redshiftPubliclyAccessible } from './redshiftPubliclyAccessible';

const cluster = (properties: object): CfnTemplate => ({
  Resources: {
    Cluster: { Type: 'AWS::Redshift::Cluster', Properties: properties },
  },
});

describe('redshift-publicly-accessible', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [redshiftPubliclyAccessible]);

  it('flags a publicly accessible cluster (boolean or string form)', () => {
    expect(run(cluster({ PubliclyAccessible: true }))).toHaveLength(1);
    expect(run(cluster({ PubliclyAccessible: 'true' }))).toHaveLength(1);
  });

  it('does not flag private, default, or intrinsic values', () => {
    expect(run(cluster({ PubliclyAccessible: false }))).toHaveLength(0);
    expect(run(cluster({}))).toHaveLength(0);
    expect(
      run(cluster({ PubliclyAccessible: { 'Fn::If': ['X', true, false] } }))
    ).toHaveLength(0);
  });
});
