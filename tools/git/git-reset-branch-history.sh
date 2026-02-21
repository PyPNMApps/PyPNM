#!/usr/bin/env bash
set -euo pipefail

# git-reset-branch-history.sh
#
# Generic helper to hard-reset a Git branch on a remote to a brand-new
# orphan history, using the current working tree as the new initial commit.
#
# WARNING: This script force-pushes and rewrites history on the target branch.
# By default it creates a backup branch first, unless --no-backup is used.

SCRIPT_NAME="$(basename "$0")"

REMOTE="origin"
BRANCH="main"
COMMIT_MESSAGE="Initial clean commit"
ALLOW_DIRTY_WORKTREE="0"
CREATE_BACKUP="1"

usage() {
  cat <<EOF
$SCRIPT_NAME - Rewrite A Git Branch As A Fresh Orphan History

Usage:
  $SCRIPT_NAME [options]

Options:
  --remote NAME          Remote name to push to (default: origin)
  --branch NAME          Branch name to rewrite (default: main)
  --message TEXT         Commit message for the new initial commit
                         (default: "Initial clean commit")
  --allow-dirty          Allow running with a dirty working tree.
                         By default, the script aborts if there are
                         uncommitted changes.
  --no-backup            Do NOT create a backup branch before rewriting.
                         By default, a backup branch is created and pushed.
  --help, -h             Show this help message and exit.

Description:
  This script will:

    1. Verify you are inside a git repository.
    2. Ensure the working tree is clean (unless --allow-dirty is used).
    3. Fetch the latest refs from the remote.
    4. Check out the target branch.
    5. Optionally create a BACKUP BRANCH from the current tip of the
       target branch and push it to the remote:
         <branch>-backup-YYYYMMDD-HHMMSS
    6. Create an orphan branch with the current working tree contents.
    7. Commit those contents as a new initial commit.
    8. Rename the orphan branch to the target branch.
    9. Force-push the rewritten branch to the remote.

IMPORTANT:
  - Make sure branch protections on the remote allow force-push.
  - Only run this if you are sure you want to reset the branch history.
  - Omit --no-backup if you want a safety net.

Examples:

  Rewrite main on origin with a clean initial commit (with backup):

    $SCRIPT_NAME

  Rewrite main on origin without creating a backup branch:

    $SCRIPT_NAME --no-backup

  Rewrite branch "develop" on remote "upstream" with a custom message:

    $SCRIPT_NAME --remote upstream --branch develop --message "Fresh start"
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --remote)
      REMOTE="$2"
      shift 2
      ;;
    --branch)
      BRANCH="$2"
      shift 2
      ;;
    --message)
      COMMIT_MESSAGE="$2"
      shift 2
      ;;
    --allow-dirty)
      ALLOW_DIRTY_WORKTREE="1"
      shift 1
      ;;
    --no-backup)
      CREATE_BACKUP="0"
      shift 1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      echo
      usage
      exit 1
      ;;
  esac
done

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: This script must be run inside a git repository."
  exit 1
fi

if [[ "$ALLOW_DIRTY_WORKTREE" != "1" ]]; then
  if [[ -n "$(git status --porcelain)" ]]; then
    echo "ERROR: Working tree is not clean."
    echo "       Commit, stash, or discard changes before running this script,"
    echo "       or re-run with --allow-dirty if you are sure."
    exit 1
  fi
fi

echo "Remote: $REMOTE"
echo "Branch: $BRANCH"
echo
if [[ "$CREATE_BACKUP" == "1" ]]; then
  echo "This will:"
  echo "  - Create a BACKUP branch from the current '$BRANCH' tip on '$REMOTE'"
  echo "  - Create a NEW orphan history for branch '$BRANCH'"
  echo "  - Use the CURRENT WORKING TREE as the new initial commit"
  echo "  - FORCE-PUSH the rewritten branch to remote '$REMOTE'"
  echo
  echo "The previous history of '$BRANCH' on '$REMOTE' will no longer be"
  echo "referenced by '$BRANCH', but will remain available via the backup branch."
else
  echo "This will:"
  echo "  - Create a NEW orphan history for branch '$BRANCH'"
  echo "  - Use the CURRENT WORKING TREE as the new initial commit"
  echo "  - FORCE-PUSH the rewritten branch to remote '$REMOTE'"
  echo
  echo "No backup branch will be created; previous history will not be"
  echo "referenced by '$BRANCH' or any new backup."
fi
echo
read -r -p "Type YES to continue: " CONFIRM

if [[ "$CONFIRM" != "YES" ]]; then
  echo "Aborted by user."
  exit 1
fi

echo "Fetching latest refs from '$REMOTE'..."
git fetch "$REMOTE"

echo "Checking out branch '$BRANCH'..."
git checkout "$BRANCH"

echo "Pulling latest from '$REMOTE/$BRANCH'..."
git pull "$REMOTE" "$BRANCH"

BACKUP_BRANCH=""
if [[ "$CREATE_BACKUP" == "1" ]]; then
  CURRENT_COMMIT="$(git rev-parse HEAD)"
  TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
  BACKUP_BRANCH="${BRANCH}-backup-${TIMESTAMP}"

  echo "Creating backup branch '$BACKUP_BRANCH' at $CURRENT_COMMIT..."
  git branch "$BACKUP_BRANCH" "$CURRENT_COMMIT"

  echo "Pushing backup branch '$BACKUP_BRANCH' to remote '$REMOTE'..."
  git push "$REMOTE" "$BACKUP_BRANCH"
fi

ORPHAN_BRANCH="__orphan_reset_${BRANCH}"

echo "Creating orphan branch '$ORPHAN_BRANCH'..."
git checkout --orphan "$ORPHAN_BRANCH"

echo "Staging all files for new initial commit..."
git add -A

echo "Creating new initial commit..."
git commit -m "$COMMIT_MESSAGE"

echo "Renaming orphan branch '$ORPHAN_BRANCH' to '$BRANCH'..."
git branch -M "$BRANCH"

echo "Force-pushing rewritten branch '$BRANCH' to remote '$REMOTE'..."
git push -f "$REMOTE" "$BRANCH"

echo
echo "Done."
echo "Branch '$BRANCH' on '$REMOTE' now has a fresh history with a new initial commit."
if [[ "$CREATE_BACKUP" == "1" ]]; then
  echo "Previous history is preserved on backup branch: $BACKUP_BRANCH"
  echo "You can delete the backup branch later if you are sure it is no longer needed."
else
  echo "No backup branch was created (per --no-backup). Previous history is only"
  echo "recoverable from any existing clones or reflogs."
fi
