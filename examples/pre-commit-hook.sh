#!/bin/bash
# Apex Debug pre-commit hook
# Place this in .git/hooks/pre-commit (and make it executable)

echo "Running Apex Debug on staged changes..."

# Only analyze Python files that are staged
STAGED_PY=$(git diff --cached --name-only --diff-filter=ACM | grep '\.py$' || true)

if [ -z "$STAGED_PY" ]; then
    echo "No Python files staged. Skipping."
    exit 0
fi

# Run apex on staged changes only
apex analyze . --diff-staged --min-severity medium

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "Apex Debug found issues. Commit blocked."
    echo "Run 'apex analyze . --diff-staged --fix-dry-run' to see auto-fix suggestions."
    echo "Run 'apex analyze . --diff-staged --fix' to apply safe fixes."
    exit 1
fi

echo "Apex Debug passed."
exit 0
