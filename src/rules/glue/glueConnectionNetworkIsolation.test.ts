import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { glueConnectionNetworkIsolation } from './glueConnectionNetworkIsolation';

describe('glue-connection-network-isolation', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [glueConnectionNetworkIsolation]);

  const connection = (input: object): CfnTemplate => ({
    Resources: {
      Conn: {
        Type: 'AWS::Glue::Connection',
        Properties: { CatalogId: '1', ConnectionInput: input },
      },
    },
  });

  it('flags a JDBC connection with no subnet and no SSL (two findings)', () => {
    expect(
      run(
        connection({
          ConnectionType: 'JDBC',
          ConnectionProperties: {
            JDBC_CONNECTION_URL: 'jdbc:mysql://db:3306/x',
          },
        })
      )
    ).toHaveLength(2);
  });

  it('does not flag an isolated SSL-enforcing connection', () => {
    expect(
      run(
        connection({
          ConnectionType: 'JDBC',
          ConnectionProperties: {
            JDBC_CONNECTION_URL: 'jdbc:mysql://db:3306/x',
            JDBC_ENFORCE_SSL: 'true',
          },
          PhysicalConnectionRequirements: { SubnetId: 'subnet-1' },
        })
      )
    ).toHaveLength(0);
  });

  it('recognizes SSL in the URL and skips non-JDBC connections', () => {
    expect(
      run(
        connection({
          ConnectionType: 'JDBC',
          ConnectionProperties: {
            JDBC_CONNECTION_URL: 'jdbc:postgresql://db/x?sslmode=require',
          },
          PhysicalConnectionRequirements: { SubnetId: 'subnet-1' },
        })
      )
    ).toHaveLength(0);
    expect(run(connection({ ConnectionType: 'NETWORK' }))).toHaveLength(0);
  });
});
