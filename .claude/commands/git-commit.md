---
description: Analyze current changes and create a well-formatted commit
---

You are tasked with creating a git commit based on the current changes in the repository.

Follow these steps:

1. **Analyze the changes:**
   - Run `git status` to see all modified, added, and deleted files
   - Run `git diff` to see unstaged changes
   - Run `git diff --staged` to see staged changes
   - Review ALL changes to understand the full scope of modifications

2. **Draft a commit message** following this structure:

   ```
   <one-line summary in imperative mood, max 72 chars>

   <blank line>

   <detailed explanation if needed, including:>
   - Background/motivation for the changes
   - Overview of what was modified
   - Important implementation details
   - Any breaking changes or side effects
   ```

   **Commit message guidelines:**
   - First line: Clear, concise summary in imperative mood (e.g., "Add feature" not "Added feature")
   - Use Chinese or English based on the content and project context
   - If changes span multiple areas, use bullet points to list them
   - Include technical context that isn't obvious from the diff
   - Mention related test changes or configuration updates

3. **Stage and commit:**
   - Stage all relevant changes using `git add`
   - Create the commit with your drafted message 
   - After creating the commit, run `git commit --amend -s` to add your Signed-off-by signature
   - Do NOT push to remote (just create the local commit)

4. **Verify:**
   - Run `git status` to confirm the commit was created
   - Run `git log -1` to show the final commit with your signature

IMPORTANT:
- Do NOT create any documentation files or README updates
- Do NOT use the TodoWrite tool
- Focus only on analyzing changes and creating the commit
- If there are no changes to commit, inform the user clearly
- Do NOT include Claude Code signature or Co-Authored-By information in commit messages
- ALWAYS run `git commit --amend -s` after creating the commit to add Signed-off-by
