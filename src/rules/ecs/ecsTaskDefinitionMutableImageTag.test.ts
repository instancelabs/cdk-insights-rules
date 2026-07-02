import { describe, expect, it } from 'vitest';
import { runRules } from '../../runRules';
import type { CfnTemplate } from '../../types';
import { ecsTaskDefinitionMutableImageTag } from './ecsTaskDefinitionMutableImageTag';

describe('ecs-task-definition-mutable-image-tag', () => {
  const run = (template: CfnTemplate) =>
    runRules(template, [ecsTaskDefinitionMutableImageTag]);

  const res = (properties: object): CfnTemplate => ({
    Resources: {
      R: { Type: 'AWS::ECS::TaskDefinition', Properties: { ...properties } },
    },
  });

  const containers = (image: unknown) => ({
    ContainerDefinitions: [{ Name: 'app', Image: image }],
  });

  it('flags latest and untagged images', () => {
    expect(run(res(containers('nginx:latest')))).toHaveLength(1);
    expect(run(res(containers('nginx')))).toHaveLength(1);
  });

  it('does not flag pinned tags, digests, or intrinsic asset images', () => {
    expect(run(res(containers('nginx:1.27.3')))).toHaveLength(0);
    expect(run(res(containers('nginx@sha256:abc123')))).toHaveLength(0);
    expect(run(res(containers({ 'Fn::Sub': '${Repo}:${Tag}' })))).toHaveLength(
      0
    );
  });
});
