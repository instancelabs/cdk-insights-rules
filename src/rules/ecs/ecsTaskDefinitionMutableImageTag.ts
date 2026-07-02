import type { Rule } from '../../types';

/**
 * Classify a container image reference. Intrinsics (CDK asset images) are
 * digest-pinned by construction and return null.
 */
const classifyImage = (image: unknown): 'latest' | 'untagged' | null => {
  if (typeof image !== 'string') {
    return null;
  }
  if (image.includes('@sha256:') || image.includes('@sha512:')) {
    return null;
  }
  const lastSegment = image.slice(image.lastIndexOf('/') + 1);
  const colon = lastSegment.lastIndexOf(':');
  if (colon === -1) {
    return 'untagged';
  }
  return lastSegment.slice(colon + 1) === 'latest' ? 'latest' : null;
};

/**
 * ecs-task-definition-mutable-image-tag
 *
 * `:latest` (or no tag, which means latest) makes deployments
 * non-reproducible: a service restart can silently pull different code.
 */
export const ecsTaskDefinitionMutableImageTag: Rule = {
  metadata: {
    ruleId: 'ecs-task-definition-mutable-image-tag',
    name: 'ECS Mutable Image Tag',
    description:
      'Detects ECS containers referencing images by the mutable latest tag or with no tag.',
    severity: 'LOW',
    wafPillar: 'Operational Excellence',
    resourceTypes: ['AWS::ECS::TaskDefinition'],
    awsDocUrl:
      'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-type-ecs.html',
    remediationSteps: [
      'Pin images to an immutable version tag or a digest (@sha256:...)',
    ],
  },

  check: (template, report) => {
    for (const [resourceId, resource] of Object.entries(
      template.Resources ?? {}
    )) {
      if (resource.Type !== 'AWS::ECS::TaskDefinition') {
        continue;
      }
      const containers = resource.Properties?.ContainerDefinitions;
      if (!Array.isArray(containers)) {
        continue;
      }
      for (const container of containers) {
        const kind = classifyImage(container?.Image);
        if (!kind) {
          continue;
        }
        const name = container?.Name ?? '(unnamed)';
        report(resourceId, {
          issue:
            kind === 'latest'
              ? `ECS container "${name}" uses the mutable "latest" image tag.`
              : `ECS container "${name}" references an image with no tag (implicitly latest).`,
          recommendation:
            'Pin the image to a version tag or digest so restarts and scale-outs run exactly the code that was deployed.',
        });
      }
    }
  },

  example: {
    flagged: `import * as ecs from 'aws-cdk-lib/aws-ecs';

new ecs.CfnTaskDefinition(this, 'TaskDef', {
  cpu: '256',
  memory: '512',
  containerDefinitions: [
    { name: 'app', image: 'public.ecr.aws/nginx/nginx:latest' },
  ],
});`,
    fixed: `import * as ecs from 'aws-cdk-lib/aws-ecs';

new ecs.CfnTaskDefinition(this, 'TaskDef', {
  cpu: '256',
  memory: '512',
  containerDefinitions: [
    { name: 'app', image: 'public.ecr.aws/nginx/nginx:1.27.3' },
  ],
});`,
  },
};
