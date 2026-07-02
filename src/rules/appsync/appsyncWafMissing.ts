import type { Rule } from '../../types';

/** Collect every logical id referenced anywhere in a value (Ref/GetAtt/Sub). */
const collectReferencedIds = (value: unknown, out: Set<string>): void => {
  if (value == null) {
    return;
  }
  if (typeof value === 'string') {
    out.add(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      collectReferencedIds(item, out);
    }
    return;
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    if (typeof obj.Ref === 'string') {
      out.add(obj.Ref);
    }
    const getAtt = obj['Fn::GetAtt'];
    if (Array.isArray(getAtt) && typeof getAtt[0] === 'string') {
      out.add(getAtt[0]);
    } else if (typeof getAtt === 'string') {
      out.add(getAtt.split('.')[0]);
    }
    const sub = obj['Fn::Sub'];
    const subStr = Array.isArray(sub) ? sub[0] : sub;
    if (typeof subStr === 'string') {
      for (const match of subStr.matchAll(
        /\$\{([A-Za-z0-9]+)(?:\.[^}]*)?\}/g
      )) {
        out.add(match[1]);
      }
    }
  }
};

/**
 * appsync-waf-missing
 *
 * A GraphQL API is a single endpoint fronting your whole data graph; WAF
 * association is the standard defence against injection and abuse. An API
 * counts as covered when a WAFv2 WebACLAssociation in the template
 * references it (via Ref, GetAtt, or Sub).
 */
export const appsyncWafMissing: Rule = {
  metadata: {
    ruleId: 'appsync-waf-missing',
    name: 'AppSync WAF Missing',
    description:
      'Detects AppSync GraphQL APIs without a WAF WebACL association.',
    severity: 'MEDIUM',
    wafPillar: 'Security',
    resourceTypes: [
      'AWS::AppSync::GraphQLApi',
      'AWS::WAFv2::WebACLAssociation',
    ],
    awsDocUrl:
      'https://docs.aws.amazon.com/appsync/latest/devguide/WAF-Integration.html',
    remediationSteps: [
      'Create an AWS::WAFv2::WebACLAssociation linking a WebACL to the GraphQL API ARN',
    ],
    complianceFrameworks: ['SOC2', 'HIPAA', 'PCI-DSS', 'NIST'],
  },

  check: (template, report) => {
    const entries = Object.entries(template.Resources ?? {});
    const associatedIds = new Set<string>();
    for (const [, resource] of entries) {
      if (resource.Type === 'AWS::WAFv2::WebACLAssociation') {
        collectReferencedIds(resource.Properties?.ResourceArn, associatedIds);
      }
    }
    for (const [resourceId, resource] of entries) {
      if (resource.Type !== 'AWS::AppSync::GraphQLApi') {
        continue;
      }
      if (!associatedIds.has(resourceId)) {
        report(resourceId, {
          issue: 'AppSync GraphQL API has no WAF WebACL associated.',
          recommendation:
            'Associate a WAFv2 WebACL with the API to protect against injection, abusive queries, and DDoS traffic.',
        });
      }
    }
  },

  example: {
    flagged: `import * as appsync from 'aws-cdk-lib/aws-appsync';

new appsync.CfnGraphQLApi(this, 'Api', {
  name: 'my-api',
  authenticationType: 'AWS_IAM',
});`,
    fixed: `import * as appsync from 'aws-cdk-lib/aws-appsync';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';

const api = new appsync.CfnGraphQLApi(this, 'Api', {
  name: 'my-api',
  authenticationType: 'AWS_IAM',
});
new wafv2.CfnWebACLAssociation(this, 'WafAssociation', {
  resourceArn: api.attrArn,
  webAclArn:
    'arn:aws:wafv2:eu-west-2:111122223333:regional/webacl/api-acl/1234',
});`,
  },
};
