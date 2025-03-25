# Git Checks

- `git reset` - Reset current HEAD to the specified state. you can lose your changes if the changes are not committed.
- `git rm` - Remove files matching pathspec from the index.
- `git rm *` - This command will delete all files and prompts for confirmation.
- `git clean -fd` - This command will remove all untracked files and directories and prompts for confirmation.
- `git push -f` - This command will force push and overwrite remote history and prompts for confirmation.
- `git branch -D {BRANCH}` - This command will force delete a branch and prompts for confirmation.
- `git checkout -f` - This command will force checkout and discard local changes and prompts for confirmation.
- `git rebase -i` - This command will start an interactive rebase which can modify commit history and prompts for confirmation.
- `git filter-branch` - This command will rewrite Git history and can be dangerous if used incorrectly, prompting for confirmation.
- `git gc --prune=now` - This command will permanently delete unreachable objects and prompts for confirmation.
- `git update-ref -d {REF}` - This command will delete a Git reference and prompts for confirmation.
- `git merge --no-ff` - This command will perform a non-fast-forward merge or abort an ongoing merge and prompts for confirmation.
- `git cherry-pick {COMMIT}` - This command will apply changes from existing commits to the current branch and prompts for confirmation.
- `git bisect` - This command will start a binary search to find a commit that introduced a bug and prompts for confirmation.
- `git worktree add/remove {PATH}` - This command will add or remove a Git worktree and prompts for confirmation.
