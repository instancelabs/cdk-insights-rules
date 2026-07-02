/**
 * Shared helpers for reading CloudFormation property values safely.
 *
 * Templates aren't only produced by CDK — SAM and hand-written CloudFormation
 * are valid inputs too, and those routinely contain intrinsic functions
 * (`Ref`, `Fn::If`, ...) where a rule expects a literal, and strings ("true")
 * where a rule expects a boolean. Rules must never flag a value they cannot
 * actually decide: an unresolvable value is *unknown*, not a violation.
 */

/**
 * True when a value is a CloudFormation intrinsic (`{ Ref: ... }`,
 * `{ 'Fn::If': [...] }`, etc.) whose resolved value can't be known from the
 * template alone. Rules should skip — not flag — such values.
 */
export const isIntrinsic = (value: unknown): boolean => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const keys = Object.keys(value);
  return keys.length === 1 && (keys[0] === 'Ref' || keys[0].startsWith('Fn::'));
};

/**
 * Normalize a CloudFormation boolean. CloudFormation accepts the strings
 * "true"/"false" wherever a boolean is expected, so `=== true` alone both
 * misses `"true"` and wrongly flags it. Returns `undefined` for anything that
 * isn't decidably boolean (including intrinsics).
 */
export const asBoolean = (value: unknown): boolean | undefined => {
  if (typeof value === 'boolean') {
    return value;
  }
  if (value === 'true') {
    return true;
  }
  if (value === 'false') {
    return false;
  }
  return undefined;
};

/**
 * Logical-id patterns of resources the CDK framework synthesizes internally —
 * log-retention handlers, auto-delete-objects providers, custom-resource
 * framework functions. Users cannot configure these constructs, so advisory
 * rules (e.g. "enable tracing") must not flag them: a finding the user cannot
 * act on erodes trust in every other finding.
 */
const CDK_INTERNAL_LOGICAL_ID_PATTERNS: RegExp[] = [
  /^LogRetention[0-9a-f]{32}/, // aws-lambda logRetention singleton
  /^CustomS3AutoDeleteObjectsCustomResourceProvider/, // s3 autoDeleteObjects
  /^CustomCDKBucketDeployment[0-9a-f]+/, // s3-deployment handler
  /^AWS679f53fac002430cb0da5b7982bd2287/, // AwsCustomResource singleton
  /framework(onEvent|isComplete|onTimeout)/i, // custom-resources Provider
  /CustomResourceProviderHandler/, // core CustomResourceProvider
];

/**
 * True when a logical id matches a known CDK-internal helper resource.
 * Heuristic by nature; the patterns are the stable, hash-suffixed names CDK
 * has used for years. A false negative here just means one extra finding.
 */
export const isCdkInternalLogicalId = (logicalId: string): boolean =>
  CDK_INTERNAL_LOGICAL_ID_PATTERNS.some((pattern) => pattern.test(logicalId));
