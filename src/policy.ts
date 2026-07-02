/**
 * Shared helpers for reading IAM-style policy documents (key policies, secret
 * resource policies, bucket policies, role policies). Ported from the CDK
 * Insights product so open rules and the product agree on what "public" means.
 */

/** A single IAM-style policy statement, loosely typed like the template. */
export interface PolicyStatement {
  Effect?: unknown;
  Principal?: unknown;
  NotPrincipal?: unknown;
  Action?: unknown;
  Resource?: unknown;
  Condition?: unknown;
  [key: string]: unknown;
}

/**
 * Normalize a policy document to a statement array. Accepts the document as
 * an object or a JSON string (raw CloudFormation allows both), and a
 * `Statement` that is a single object or an array.
 */
export const asStatements = (document: unknown): PolicyStatement[] => {
  let doc = document;
  if (typeof doc === 'string') {
    try {
      doc = JSON.parse(doc);
    } catch {
      return [];
    }
  }
  if (!doc || typeof doc !== 'object') {
    return [];
  }
  const statement = (doc as Record<string, unknown>).Statement;
  if (Array.isArray(statement)) {
    return statement.filter(
      (entry): entry is PolicyStatement => !!entry && typeof entry === 'object'
    );
  }
  return statement && typeof statement === 'object'
    ? [statement as PolicyStatement]
    : [];
};

/**
 * True when a Principal grants to the world: the literal `"*"`, or a principal
 * map any of whose values is (or contains) `"*"` — e.g. `{ AWS: "*" }`.
 */
export const isWildcardPrincipal = (principal: unknown): boolean => {
  if (principal === '*') {
    return true;
  }
  if (principal && typeof principal === 'object' && !Array.isArray(principal)) {
    return Object.values(principal).some((value) =>
      Array.isArray(value) ? value.includes('*') : value === '*'
    );
  }
  return false;
};

/**
 * Condition keys that scope a wildcard-principal grant back to an account,
 * organisation, or source — making it broad but not public.
 */
const SCOPING_CONDITION_KEYS = new Set([
  'aws:PrincipalAccount',
  'aws:PrincipalOrgID',
  'aws:PrincipalArn',
  'aws:SourceAccount',
  'aws:SourceArn',
  'kms:CallerAccount',
]);

/** True when a statement Condition contains any scoping condition key. */
export const hasScopingCondition = (condition: unknown): boolean => {
  if (!condition || typeof condition !== 'object') {
    return false;
  }
  for (const operands of Object.values(condition)) {
    if (!operands || typeof operands !== 'object') {
      continue;
    }
    for (const conditionKey of Object.keys(operands)) {
      if (SCOPING_CONDITION_KEYS.has(conditionKey)) {
        return true;
      }
    }
  }
  return false;
};

/**
 * True when a statement grants the world access: an Allow to a wildcard
 * principal, with no NotPrincipal carve-out and no Condition scoping it back
 * to an account/org/source. Deny statements never match.
 */
export const isPublicStatement = (statement: PolicyStatement): boolean =>
  statement.Effect === 'Allow' &&
  statement.NotPrincipal === undefined &&
  isWildcardPrincipal(statement.Principal) &&
  !hasScopingCondition(statement.Condition);
