# MCP Configuration Instructions

This file explains how to configure Model Context Protocol (MCP) servers
for your project. It is generated from a template and tailored for each project.

---

## 1. Local Filesystem MCP

- **Purpose**: Allows Claude Code to navigate the project file tree efficiently
- **Root directory**: /Users/rick/Work/github/kms-demo
- **Server command**:
```bash
npx @modelcontextprotocol/server-filesystem --path "/Users/rick/Work/github/kms-demo"
```

## 2. GitHub MCP (optional)
- **Purpose**: Efficient issue management, pull request creation, and repository analysis
- **Repository**: git@github.com:pchikoian/kms-demo.git
- **Required**: GITHUB_TOKEN environment variable

```bash
export GITHUB_TOKEN=<your-token>
```
- **Add MCP server command**:
```
claude mcp add github --transport http "git@github.com:pchikoian/kms-demo.git"
```
⚠️ If `GITHUB_TOKEN` is not set, GitHub MCP will not work.

## 3. Local Git MCP (optional)
- **Purpose**: Analyze commit history, blame, logs.
- **Root directory**: /Users/rick/Work/github/kms-demo
- **Server command**:
```bash
npx @modelcontextprotocol/server-git --path "/Users/rick/Work/github/kms-demo"
```

## Best Practices
1. Load skills once per session - avoids unnecessary token usage
2. Batch operations - process multiple files/issues together
3. Use MCP whenever possible - more efficient than shell commands
4. Keep this file updated - helps onboarding new contributors

**Notes**:

- Replace `<your-token>` with a valid GitHub Personal Access Token (PAT).
- For more info on creating a PAT and setting up MCP, see:
  - [GitHub Docs: Personal Access Tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
  - [Model Context Protocol Docs](https://modelcontextprotocol.io/docs/getting-started/intro)
