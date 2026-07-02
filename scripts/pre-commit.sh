#!/bin/bash
# Pre-commit checks for cdk-insights-rules.
# Runs the fast gates (lint + typecheck), then — on main only — reminds you to
# bump the version so the merge auto-publishes (release.yml is version-gated).
# The bump prompt is interactive-only; non-interactive commits and CI never hang.
set -e

echo "🔍 Running pre-commit checks..."
echo "🧹 Lint..."
npm run lint
echo "🧪 Typecheck..."
npm run typecheck

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
if [ "$CURRENT_BRANCH" != "main" ]; then
  echo "ℹ️  Not on main — skipping version-bump reminder."
  exit 0
fi

# Skip for release / version-bump commits themselves.
COMMIT_MSG=$(cat .git/COMMIT_EDITMSG 2>/dev/null || echo "")
case "$COMMIT_MSG" in
  "chore: release"* | "chore: bump"* | "chore(release)"*)
    echo "ℹ️  Release commit — skipping bump."
    exit 0
    ;;
esac

# Nothing to release if only meta files changed.
STAGED=$(git diff --cached --name-only | grep -vE '^(package\.json|package-lock\.json|CHANGELOG\.md)$' || true)
if [ -z "$STAGED" ]; then
  exit 0
fi

# If package.json is already staged, assume the version was handled deliberately.
if git diff --cached --name-only | grep -q '^package\.json$'; then
  echo "ℹ️  package.json staged — assuming the version is handled."
  exit 0
fi

# Only prompt with a real terminal; otherwise remind and continue (never block).
if [ ! -t 1 ] || [ ! -r /dev/tty ]; then
  echo "ℹ️  Code changed on main without a version bump."
  echo "    Run 'npm run release:patch|minor|major' to cut a release when ready."
  exit 0
fi

echo ""
echo "📝 Code staged on main. Bump the version to publish this release?"
echo "  1) patch   2) minor   3) major   4) skip"
read -p "Choice (1-4): " -n 1 -r CHOICE </dev/tty
echo ""
case "$CHOICE" in
  1) BUMP=patch ;;
  2) BUMP=minor ;;
  3) BUMP=major ;;
  *)
    echo "⏭️  Skipping bump — remember to release later."
    exit 0
    ;;
esac

echo "🔄 Bumping $BUMP..."
npm version "$BUMP" --no-git-tag-version
npm run changelog:generate || echo "⚠️  changelog:generate skipped"
git add package.json package-lock.json CHANGELOG.md
echo "✅ Version bumped + changelog updated, added to this commit."
