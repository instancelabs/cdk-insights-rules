import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { lambdaUrlAuthNone } from '../rules/lambda/lambdaUrlAuthNone';
import { CdkInsightsRulesPlugin } from './plugin';

describe('CdkInsightsRulesPlugin', () => {
  let workDir: string;

  beforeEach(() => {
    workDir = mkdtempSync(join(tmpdir(), 'cdki-plugin-'));
  });
  afterEach(() => {
    rmSync(workDir, { recursive: true, force: true });
  });

  const writeTemplate = (template: object): string => {
    const templatePath = join(workDir, 'template.json');
    writeFileSync(templatePath, JSON.stringify(template));
    return templatePath;
  };

  it('reports a violation for a flagged template', () => {
    const templatePath = writeTemplate({
      Resources: {
        Url: { Type: 'AWS::Lambda::Url', Properties: { AuthType: 'NONE' } },
      },
    });

    const report = new CdkInsightsRulesPlugin().validate({
      templatePaths: [templatePath],
    });

    expect(report.success).toBe(false);
    const violation = report.violations.find(
      (candidate) => candidate.ruleName === 'lambda-url-auth-none'
    );
    expect(violation).toBeDefined();
    expect(violation?.violatingResources[0]?.resourceLogicalId).toBe('Url');
    expect(violation?.violatingResources[0]?.templatePath).toBe(templatePath);
  });

  it('succeeds on a clean template', () => {
    const templatePath = writeTemplate({
      Resources: {
        Url: { Type: 'AWS::Lambda::Url', Properties: { AuthType: 'AWS_IAM' } },
      },
    });

    const report = new CdkInsightsRulesPlugin().validate({
      templatePaths: [templatePath],
    });

    expect(report.success).toBe(true);
    expect(report.violations).toHaveLength(0);
  });

  it('drops violations below minimumSeverity', () => {
    // s3-bucket-versioning-disabled is MEDIUM.
    const templatePath = writeTemplate({
      Resources: { Bucket: { Type: 'AWS::S3::Bucket', Properties: {} } },
    });

    const high = new CdkInsightsRulesPlugin({
      minimumSeverity: 'HIGH',
    }).validate({ templatePaths: [templatePath] });
    expect(high.violations).toHaveLength(0);

    const low = new CdkInsightsRulesPlugin({ minimumSeverity: 'LOW' }).validate(
      {
        templatePaths: [templatePath],
      }
    );
    expect(low.violations.map((violation) => violation.ruleName)).toContain(
      's3-bucket-versioning-disabled'
    );
  });

  it('runs only the rules it is given', () => {
    const templatePath = writeTemplate({
      Resources: {
        Url: { Type: 'AWS::Lambda::Url', Properties: { AuthType: 'NONE' } },
        Bucket: { Type: 'AWS::S3::Bucket', Properties: {} },
      },
    });

    const report = new CdkInsightsRulesPlugin({
      rules: [lambdaUrlAuthNone],
    }).validate({ templatePaths: [templatePath] });

    expect(report.violations.map((violation) => violation.ruleName)).toEqual([
      'lambda-url-auth-none',
    ]);
  });
});
