// Canonical source: instancelabs/software-factory, packages/factory-local/workflows.
// Repository copies and their target maps are pinned in the factory release catalogue.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const sha = (value) => typeof value === "string" && /^[a-f0-9]{40,64}$/.test(value);
const assert = (condition, message) => {
  if (!condition) throw Object.assign(new Error(message), { releaseConditionFailed: true });
};
const decode = (text) => JSON.parse(text);
const object = (value) => {
  assert(value && typeof value === "object" && !Array.isArray(value), "Expected an object");
  return value;
};
const sourceTag = "software-factory:source-commit";
const actionTag = "software-factory:action-id";

export const createReleaseProtocol = ({ run, read, write, output, now, sleep, http, env }) => {
  const checkedOut = () => run("git", ["rev-parse", "HEAD"]).stdout.trim();
  const catalogue = (commit) =>
    decode(run("git", ["show", `${commit}:.github/factory/release-targets.json`]).stdout);
  const context = (readOnly = false) => {
    const commit = checkedOut();
    assert(sha(commit), "Checkout is not an immutable commit");
    const config = catalogue(commit);
    assert(
      config.schemaVersion === 1 && config.repository === env.GITHUB_REPOSITORY,
      "Repository is not enrolled for this release protocol",
    );
    const target = config.targets.find((item) => item.id === env.FACTORY_TARGET);
    assert(target, "Release target is not enrolled");
    if (env.FACTORY_ACTION_ID) {
      assert(
        /^release-[a-f0-9]{64}$/.test(env.FACTORY_ACTION_ID),
        "Invalid factory action identity",
      );
      assert(
        sha(env.FACTORY_SOURCE_SHA) &&
          env.FACTORY_SOURCE_SHA === commit &&
          env.GITHUB_SHA === commit,
        "Factory source or workflow revision moved",
      );
      assert(
        env.GITHUB_EVENT_NAME === "workflow_dispatch",
        "Factory dispatch identity is not valid for this event",
      );
      assert(
        env.GITHUB_RUN_ATTEMPT === "1",
        "A factory release cannot be rerun under its original authority",
      );
      const deadline = Date.parse(env.FACTORY_DEADLINE);
      assert(Number.isFinite(deadline), "Factory execution deadline is missing");
      if (!readOnly)
        assert(
          now().getTime() < deadline,
          "Factory authority expired while the workflow was queued",
        );
    }
    const source = env.RELEASE_SHA || env.FACTORY_SOURCE_SHA || env.GITHUB_SHA;
    assert(sha(source) && source === commit, "Release source differs from the checkout");
    return { config, target, commit };
  };
  const manifest = (commit) => {
    const expected = run("git", ["show", `${commit}:package.json`]).stdout;
    assert(read("package.json") === expected, "Package identity changed during the build");
    return object(decode(expected));
  };
  const versionFor = (target, commit) => {
    const pkg = manifest(commit);
    assert(/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(pkg.version), "Package version is invalid");
    if (env.FACTORY_VERSION)
      assert(
        env.FACTORY_VERSION === pkg.version,
        "Factory version differs from the reviewed manifest",
      );
    const requested =
      env.FACTORY_TAG || (env.GITHUB_REF?.startsWith("refs/tags/") ? env.GITHUB_REF.slice(10) : "");
    if (requested)
      assert(
        requested === `v${pkg.version}`,
        "Requested tag differs from the reviewed package version",
      );
    if (target.kind === "npm")
      assert(pkg.name === target.packageName, "Package name differs from the enrolled destination");
    const channel =
      target.kind === "github-action" ? "version-tag" : env.FACTORY_CHANNEL || "latest";
    assert(
      target.kind === "github-action" || target.channels.includes(channel),
      "Distribution channel is not enrolled",
    );
    if (target.kind === "npm") {
      assert(
        ["public", "restricted"].includes(target.access) &&
          pkg.publishConfig?.access === target.access,
        "Package visibility differs from the enrolled publication policy",
      );
      assert(
        !pkg.publishConfig?.registry ||
          /^https:\/\/registry\.npmjs\.org\/?$/.test(pkg.publishConfig.registry),
        "Package publishConfig selects another registry",
      );
      assert(
        !pkg.publishConfig?.tag || pkg.publishConfig.tag === channel,
        "Package publishConfig selects another release channel",
      );
    }
    return { pkg, version: pkg.version, channel };
  };
  const aws = (target, args) =>
    decode(
      run("aws", [...args, "--region", target.region, "--output", "json", "--no-cli-pager"]).stdout,
    );
  const identity = (target) =>
    assert(
      aws(target, ["sts", "get-caller-identity"]).Account === target.accountId,
      "AWS account differs from the exact release target",
    );
  const guard = (readOnly = false) => {
    const value = context(readOnly);
    if (["npm", "github-action"].includes(value.target.kind))
      versionFor(value.target, value.commit);
    return value;
  };
  const stamp = () => {
    const { target, commit } = guard();
    assert(
      env.FACTORY_ACTION_ID && target.kind === "cloudformation" && typeof write === "function",
      "Only an approved factory CloudFormation release may bind a deployment assembly",
    );
    const assembly = object(decode(read("cdk.out/manifest.json")));
    const configuration = object(decode(read("cdk.json")));
    const artifacts = Object.entries(object(assembly.artifacts));
    assert(
      !artifacts.some(([, artifact]) => artifact.type === "cdk:cloud-assembly"),
      "Nested cloud assemblies need an explicitly qualified release route",
    );
    const stacks = artifacts.filter(([, artifact]) => artifact.type === "aws:cloudformation:stack");
    assert(stacks.length > 0 && stacks.length <= 50, "Deployment assembly stack scope is invalid");
    let override;
    if (configuration.tags !== undefined) {
      assert(Array.isArray(configuration.tags), "CDK CLI tag overrides must use Key/Value entries");
      override = Object.fromEntries(
        configuration.tags.map((tag) => {
          assert(
            typeof tag.Key === "string" && typeof tag.Value === "string",
            "Invalid CDK tag override",
          );
          return [tag.Key, tag.Value];
        }),
      );
    }
    const names = [];
    for (const [id, artifact] of stacks) {
      const properties = object(artifact.properties);
      const environment = /^aws:\/\/([^/]+)\/([^/]+)$/.exec(artifact.environment);
      assert(
        environment && environment[1] === target.accountId && environment[2] === target.region,
        "Deployment assembly selects another account or region",
      );
      names.push(properties.stackName ?? id);
      const existing =
        override && Object.keys(override).length ? override : object(properties.tags ?? {});
      assert(
        Object.values(existing).every((value) => typeof value === "string"),
        "Invalid assembly stack tags",
      );
      properties.tags = { ...existing, [sourceTag]: commit, [actionTag]: env.FACTORY_ACTION_ID };
    }
    assert(
      target.stacks?.length > 0 && target.stacks.every((name) => names.includes(name)),
      "Deployment assembly does not contain every enrolled stack",
    );
    // Deploy the already-synthesized assembly, including from existing wrapper scripts.
    // This keeps the source markers in CDK's actual stack properties, not a later AWS write.
    configuration.app = "cdk.out";
    configuration.tags = [];
    write("cdk.out/manifest.json", `${JSON.stringify(assembly, null, 2)}\n`);
    write("cdk.json", `${JSON.stringify(configuration, null, 2)}\n`);
    return { sourceCommit: commit, actionId: env.FACTORY_ACTION_ID, stacks: names };
  };
  const predeploy = () => {
    const value = guard();
    identity(value.target);
    if (env.FACTORY_ACTION_ID)
      assert(
        now().getTime() + value.target.deploymentWindowMs <= Date.parse(env.FACTORY_DEADLINE),
        "Too little approved time remains to start deployment",
      );
    for (const stack of value.target.stacks || []) {
      const result = run(
        "aws",
        [
          "cloudformation",
          "describe-stacks",
          "--stack-name",
          stack,
          "--region",
          value.target.region,
          "--output",
          "json",
          "--no-cli-pager",
        ],
        { allowFailure: true },
      );
      if (result.status !== 0) {
        assert(
          /ValidationError/.test(result.stderr) && /does not exist/.test(result.stderr),
          "Stack state could not be established",
        );
        continue;
      }
      const state = decode(result.stdout).Stacks?.[0]?.StackStatus;
      assert(
        !["ROLLBACK_COMPLETE", "DELETE_FAILED", "DELETE_IN_PROGRESS"].includes(state),
        "Destructive stack recovery is not authorised by release",
      );
    }
    return value;
  };
  const assertNpmRegistry = (packageName) => {
    const keys = ["registry"];
    if (packageName.startsWith("@")) keys.push(`${packageName.split("/")[0]}:registry`);
    for (const key of keys) {
      const value = run("npm", ["config", "get", key]).stdout.trim();
      assert(
        (key !== "registry" && value === "undefined") ||
          /^https:\/\/registry\.npmjs\.org\/?$/.test(value),
        "npm configuration selects a registry outside the approved destination",
      );
    }
  };
  const npmView = (spec, field) => {
    const result = run(
      "npm",
      ["view", spec, ...(field ? [field] : []), "--json", "--registry=https://registry.npmjs.org"],
      { allowFailure: true },
    );
    if (result.status === 0) return { found: true, value: decode(result.stdout) };
    let error;
    try {
      error = decode(result.stdout).error;
    } catch {
      error = null;
    }
    if (error?.code === "E404") return { found: false, value: null };
    throw new Error("Registry inspection failed; absence was not established");
  };
  const pack = () => {
    const value = guard();
    assert(value.target.kind === "npm", "Only npm releases can create a package artifact");
    const { pkg, version, channel } = versionFor(value.target, value.commit);
    assertNpmRegistry(pkg.name);
    assert(
      npmView(pkg.name, "name").value === pkg.name,
      "Registry package visibility/authentication is not established",
    );
    const packed = decode(run("npm", ["pack", "--json", "--ignore-scripts"]).stdout);
    assert(
      Array.isArray(packed) && packed.length === 1,
      "Package build did not produce one artifact",
    );
    const artifact = object(packed[0]);
    assert(
      /^[A-Za-z0-9._-]+\.tgz$/.test(artifact.filename) &&
        /^sha512-[A-Za-z0-9+/]+=*$/.test(artifact.integrity),
      "Package artifact identity is invalid",
    );
    const existing = npmView(`${pkg.name}@${version}`);
    if (existing.found)
      assert(
        existing.value.dist?.integrity === artifact.integrity,
        "This package version already exists with different bytes",
      );
    output("tarball", artifact.filename);
    output("integrity", artifact.integrity);
    output("version", version);
    output("package_name", pkg.name);
    output("channel", channel);
    output("already_published", existing.found ? "true" : "false");
    output("verify", "true");
    return { ...value, artifact, alreadyPublished: existing.found };
  };
  const stackSample = (target, commit) => {
    assert(
      Array.isArray(target.stacks) && target.stacks.length > 0 && target.stacks.length <= 50,
      "Expected stack coverage is absent or unbounded",
    );
    const queue = [...target.stacks];
    const seen = new Set();
    let functions = 0;
    const outputs = {};
    const revisions = new Map();
    let sourceMatches = true;
    while (queue.length) {
      const name = queue.shift();
      if (seen.has(name)) continue;
      seen.add(name);
      assert(seen.size <= 50, "Stack observation exceeded its scope");
      const stack = aws(target, ["cloudformation", "describe-stacks", "--stack-name", name])
        .Stacks?.[0];
      assert(
        stack &&
          ["CREATE_COMPLETE", "UPDATE_COMPLETE", "IMPORT_COMPLETE"].includes(stack.StackStatus),
        "Stack did not complete successfully",
      );
      const updated = stack.LastUpdatedTime ?? stack.CreationTime;
      if (typeof stack.StackId !== "string" || typeof updated !== "string")
        throw new Error("Stack revision evidence is unavailable");
      revisions.set(`stack:${stack.StackId}`, updated);
      if (target.stacks.includes(name)) {
        const tags = stack.Tags ?? [];
        sourceMatches &&= [
          [sourceTag, commit],
          [actionTag, env.FACTORY_ACTION_ID],
        ].every(
          ([key, value]) =>
            tags.filter((tag) => tag.Key === key && tag.Value === value).length === 1,
        );
      }
      for (const item of stack.Outputs || []) outputs[item.OutputKey] = item.OutputValue;
      let next;
      let pages = 0;
      do {
        if (++pages > 20)
          throw new Error("Stack-resource pagination exceeded the observation bound");
        const page = aws(target, [
          "cloudformation",
          "list-stack-resources",
          "--no-paginate",
          "--stack-name",
          name,
          ...(next ? ["--next-token", next] : []),
        ]);
        for (const resource of page.StackResourceSummaries || []) {
          if (resource.ResourceType === "AWS::CloudFormation::Stack")
            queue.push(resource.PhysicalResourceId);
          if (resource.ResourceType === "AWS::Lambda::Function") {
            assert(++functions <= 300, "Function observation exceeded its scope");
            const state = aws(target, [
              "lambda",
              "get-function-configuration",
              "--function-name",
              resource.PhysicalResourceId,
              "--query",
              "{State:State,LastUpdateStatus:LastUpdateStatus,RevisionId:RevisionId,CodeSha256:CodeSha256}",
            ]);
            assert(
              state.State === "Active" && state.LastUpdateStatus === "Successful",
              "A deployed function is not ready",
            );
            if (
              typeof state.RevisionId !== "string" ||
              !state.RevisionId ||
              typeof state.CodeSha256 !== "string" ||
              !state.CodeSha256
            )
              throw new Error("Function revision evidence is unavailable");
            revisions.set(`lambda:${resource.PhysicalResourceId}`, [
              state.RevisionId,
              state.CodeSha256,
            ]);
          }
        }
        next = page.NextToken;
      } while (next);
    }
    const revision = createHash("sha256")
      .update(JSON.stringify([...revisions].sort(([left], [right]) => left.localeCompare(right))))
      .digest("hex");
    return { stacks: seen.size, functions, outputs, sourceMatches, revision };
  };
  const alarmSample = (target) => {
    assert(target.alarms?.length > 0, "Expected alarm coverage is absent");
    const data = aws(target, ["cloudwatch", "describe-alarms", "--alarm-names", ...target.alarms]);
    const alarms = [...(data.MetricAlarms || []), ...(data.CompositeAlarms || [])];
    assert(
      target.alarms.every(
        (name) =>
          alarms.filter(
            (item) =>
              item.AlarmName === name &&
              item.AlarmArn ===
                `arn:aws:cloudwatch:${target.region}:${target.accountId}:alarm:${name}` &&
              item.StateValue === "OK",
          ).length === 1,
      ),
      "Expected alarm coverage is missing or not OK",
    );
    return `${target.alarms.length} expected alarms are OK`;
  };
  const publicProbe = async (url, expectedStatus, expectedJson) => {
    const parsed = new URL(url);
    assert(
      parsed.protocol === "https:" &&
        !parsed.username &&
        !parsed.password &&
        (parsed.hostname.endsWith(".execute-api.eu-west-2.amazonaws.com") ||
          parsed.hostname === "cdkinsights.dev" ||
          parsed.hostname.endsWith(".cdkinsights.dev") ||
          parsed.hostname === "cdkinsights.com" ||
          parsed.hostname.endsWith(".amplifyapp.com")),
      "Health endpoint is outside the approved public audience",
    );
    const result = await http(url, Boolean(expectedJson));
    assert(result.status === expectedStatus, "Health endpoint returned an unexpected status");
    if (expectedJson)
      for (const [key, value] of Object.entries(expectedJson))
        assert(result.json?.[key] === value, "Published health/version evidence does not match");
  };
  const observe = async () => {
    const { config, target, commit } = guard(true);
    const start = now();
    const criteria = [];
    const check = async (id, action) => {
      try {
        const detail = await action();
        criteria.push({ id, status: "passed", detail: String(detail || "Verified") });
      } catch (error) {
        criteria.push({
          id,
          status: error?.releaseConditionFailed === true ? "failed" : "inconclusive",
          detail: error instanceof Error ? error.message : "Verification failed",
        });
      }
    };
    criteria.push({
      id: "release-completed",
      status: env.FACTORY_RELEASE_RESULT === "success" ? "passed" : "failed",
      detail: "Required release-job outcome, separate from post-release health",
    });
    let version = null,
      channel = null,
      packageName = null;
    if (target.kind === "npm") {
      const selected = versionFor(target, commit);
      version = selected.version;
      channel = selected.channel;
      packageName = selected.pkg.name;
      assertNpmRegistry(packageName);
      let metadata;
      await check("registry-version", () => {
        if (npmView(packageName, "name").value !== packageName)
          throw new Error("Registry visibility or authentication is not established");
        const result = npmView(`${packageName}@${version}`);
        assert(
          result.found && result.value.name === packageName && result.value.version === version,
          "Exact package version is not visible",
        );
        metadata = result.value;
        return `${packageName}@${version} is visible`;
      });
      await check("artifact-integrity", () => {
        assert(
          env.FACTORY_EXPECTED_INTEGRITY &&
            metadata?.dist?.integrity === env.FACTORY_EXPECTED_INTEGRITY,
          "Published artifact does not match the built tarball",
        );
        return "Registry integrity matches the approved workflow artifact";
      });
      await check("registry-channel", () => {
        const result = npmView(packageName, "dist-tags");
        assert(
          result.found && result.value[channel] === version,
          "Registry channel does not point to this version",
        );
        return `${channel} points to ${version}`;
      });
      await check("registry-access", () => {
        const visibility = decode(
          run("npm", [
            "access",
            "get",
            "status",
            packageName,
            "--json",
            "--registry=https://registry.npmjs.org",
          ]).stdout,
        );
        assert(
          visibility[packageName] === target.access,
          "Published package visibility differs from the approved policy",
        );
        return `Package visibility is ${target.access}`;
      });
    } else if (target.kind === "github-action") {
      const selected = versionFor(target, commit);
      version = selected.version;
      channel = selected.channel;
      const resolveTag = (tag) => {
        let ref = decode(
          run("gh", ["api", `repos/${config.repository}/git/ref/tags/${tag}`]).stdout,
        ).object;
        for (let depth = 0; ref.type === "tag" && depth < 5; depth++)
          ref = decode(
            run("gh", ["api", `repos/${config.repository}/git/tags/${ref.sha}`]).stdout,
          ).object;
        assert(ref.type === "commit", "Git tag could not be resolved to a commit");
        return ref.sha;
      };
      await check("version-tag", () => {
        const release = decode(
          run("gh", ["api", `repos/${config.repository}/releases/tags/v${version}`]).stdout,
        );
        assert(
          release.draft === false && resolveTag(`v${version}`) === commit,
          "Version release/tag does not identify the approved source",
        );
        return "Version release and tag identify the source commit";
      });
      await check("major-alias", () => {
        assert(
          resolveTag(`v${version.split(".")[0]}`) === commit,
          "Rolling major alias does not identify the approved source",
        );
        return "Rolling major alias identifies the source commit";
      });
    } else {
      await check("aws-account", () => {
        identity(target);
        return `Observed account ${target.accountId} in ${target.region}`;
      });
      if (criteria.at(-1).status === "passed") {
        const samples = [];
        for (let sample = 0; sample < 3; sample++) {
          const result = {
            runtime: null,
            alarms: null,
            endpoint: null,
            revision: null,
            sourceMatches: false,
          };
          try {
            if (target.kind === "cloudformation") {
              const state = stackSample(target, commit);
              result.revision = state.revision;
              result.sourceMatches = state.sourceMatches;
              result.runtime = `${state.stacks} stacks and ${state.functions} functions ready`;
              if (target.apiOutput) {
                const base = state.outputs[target.apiOutput];
                assert(typeof base === "string", "Expected API output is missing");
                await publicProbe(
                  base.replace(/\/$/, "") + target.probe,
                  200,
                  target.healthJson ? { status: "healthy" } : null,
                );
                if (target.protectedProbe)
                  await publicProbe(base.replace(/\/$/, "") + target.protectedProbe, 401, null);
                result.endpoint = "Public health and protected-route checks passed";
              }
            } else {
              const app = aws(target, ["amplify", "get-app", "--app-id", target.appId]).app;
              assert(
                app?.repository?.replace(/\.git$/, "") ===
                  `https://github.com/${config.repository}` && app.platform === "WEB_COMPUTE",
                "Amplify application identity differs",
              );
              const branch = aws(target, [
                "amplify",
                "get-branch",
                "--app-id",
                target.appId,
                "--branch-name",
                target.branch,
              ]).branch;
              assert(
                branch?.enableAutoBuild === false,
                "Uncontrolled Amplify auto-build is enabled",
              );
              await publicProbe(
                `https://${target.domain}/jarvis-release.json?release=${commit}`,
                200,
                { commit, stage: target.stage },
              );
              await publicProbe(`https://${target.domain}/?release=${commit}`, 200, null);
              result.runtime = "Amplify app/branch and published source manifest match";
              result.endpoint = "Published website responds successfully";
            }
          } catch (error) {
            result.runtime = error;
            result.revision = error;
            if (target.apiOutput || target.kind === "amplify") result.endpoint = error;
          }
          if (target.alarms?.length) {
            try {
              result.alarms = alarmSample(target);
            } catch (error) {
              result.alarms = error;
            }
          }
          samples.push(result);
          if (sample < 2) await sleep(30000);
        }
        await check("runtime-ready", () => {
          const failure = samples.find((sample) => sample.runtime instanceof Error);
          if (failure) throw failure.runtime;
          return "Three successful target/runtime observations over at least sixty seconds";
        });
        if (target.kind === "cloudformation")
          await check("deployed-revision", () => {
            const failure = samples.find((sample) => sample.revision instanceof Error);
            if (failure) throw failure.revision;
            assert(
              samples.every((sample) => sample.sourceMatches),
              "Deployed source/action markers do not match this release",
            );
            assert(
              samples.every((sample) => sample.revision && sample.revision === samples[0].revision),
              "Deployed stack or function revision changed during observation",
            );
            return "Exact source/action markers and stable deployed revisions passed all three observations";
          });
        if (target.apiOutput || target.kind === "amplify")
          await check("endpoint-health", () => {
            const failure = samples.find((sample) => sample.endpoint instanceof Error);
            if (failure) throw failure.endpoint;
            assert(
              samples.every((sample) => sample.endpoint),
              "Endpoint coverage did not pass every observation",
            );
            return "Three successful public endpoint observations";
          });
        if (target.alarms?.length)
          await check("expected-alarms", () => {
            const failure = samples.find((sample) => sample.alarms instanceof Error);
            if (failure) throw failure.alarms;
            assert(
              samples.every((sample) => sample.alarms),
              "Alarm coverage is missing",
            );
            return "Expected alarm set passed every observation";
          });
      }
    }
    const end = now();
    const receipt = {
      schemaVersion: 1,
      repository: config.repository,
      kind: target.kind,
      sourceCommit: commit,
      runId: Number(env.GITHUB_RUN_ID),
      environmentId: target.environmentId ?? null,
      accountId: target.accountId ?? null,
      region: target.region ?? null,
      packageName,
      version,
      channel,
      windowStart: start.toISOString(),
      windowEnd: end.toISOString(),
      observedAt: end.toISOString(),
      criteria,
    };
    assert(
      Number.isSafeInteger(receipt.runId) && receipt.runId > 0,
      "Workflow run identity is missing",
    );
    return receipt;
  };
  return { guard, predeploy, stamp, pack, observe };
};

const main = async () => {
  const run = (binary, args, options = {}) => {
    assert(["git", "npm", "aws", "gh"].includes(binary), "Command is outside the release protocol");
    const result = spawnSync(binary, args, {
      encoding: "utf8",
      timeout: 120000,
      maxBuffer: 2097152,
      env: { ...process.env, AWS_PAGER: "", GH_PROMPT_DISABLED: "1" },
    });
    if (result.error || result.signal || (result.status !== 0 && !options.allowFailure))
      throw new Error(`${binary} observation/build command failed; response withheld`);
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  };
  const protocol = createReleaseProtocol({
    run,
    read: (path) => readFileSync(path, "utf8"),
    write: (path, value) => writeFileSync(path, value, "utf8"),
    output: (key, value) => {
      assert(/^[a-z_]+$/.test(key) && !/[\r\n]/.test(value), "Invalid workflow output");
      if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${key}=${value}\n`);
    },
    now: () => new Date(),
    sleep: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
    env: process.env,
    http: async (url, needsJson) => {
      const response = await fetch(url, {
        redirect: "error",
        signal: AbortSignal.timeout(20000),
        headers: { "Cache-Control": "no-cache" },
      });
      if (!needsJson) {
        await response.body?.cancel();
        return { status: response.status, json: null };
      }
      const reader = response.body?.getReader();
      let size = 0;
      const chunks = [];
      if (reader)
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.length;
          if (size > 512000) {
            await reader.cancel();
            throw new Error("Health response exceeded its bound");
          }
          chunks.push(Buffer.from(value));
        }
      const text = Buffer.concat(chunks).toString("utf8");
      let json = null;
      try {
        json = JSON.parse(text);
      } catch {}
      return { status: response.status, json };
    },
  });
  const mode = process.argv[2];
  if (mode === "guard") protocol.guard();
  else if (mode === "predeploy") protocol.predeploy();
  else if (mode === "stamp") protocol.stamp();
  else if (mode === "pack") protocol.pack();
  else if (mode === "observe") {
    const result = await protocol.observe();
    console.log(`FACTORY_RELEASE_EVIDENCE ${JSON.stringify(result)}`);
    if (result.criteria.some((item) => item.status !== "passed")) process.exitCode = 1;
  } else throw new Error("Select guard, predeploy, stamp, pack or observe");
};
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : "Release verification failed");
    process.exitCode = 1;
  });
