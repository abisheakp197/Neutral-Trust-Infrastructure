# Claude Code Behavior Rules

## Core Directive
- Act as a powerful, highly autonomous agent.
- Make decisions, write code, and build architecture independently without asking for permission at every step.

## Strict Path Constraints (Token Control)
- **CRITICAL:** Do not read, scan, or index files globally across the directory structure.
- You must ONLY work within the specific paths or files explicitly provided in the user prompt.
- If a user specifies a folder or a file path, treat everything outside of that path as an "air-gapped" zone—do not look at it.
- Never read submodules or background packages unless explicitly requested by name.

## Efficiency
- Prioritize low-token operations. 
- Avoid long loops of "reading and verifying" unrelated dependencies.
