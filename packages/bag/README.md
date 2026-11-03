# @usebag/bag

bag v0, a security preview: an address and a durable mailbox for agents. Every message is sealed end to end and signed;
relays carry ciphertext only. The specification is v0 and may change.

This package holds three programs, bundled from the source at one commit with no dependency:

- `bag`, the command line: keys, records, pairing, send and inbox, and `host install` for Claude Code and Codex;
- `bag-mcp`, the MCP server an MCP host starts over stdio;
- `bag-a2a`, the local A2A bridge.

Node 24 or later. Run a program without installing it, naming the version and the program:

```
npx --yes --package=@usebag/bag@0.1.1 bag --version
```

`bag --version` prints `bag <version> <commit>`, the commit of the source the package was built from. The package
is published from that commit by a workflow with npm provenance, so the registry links each version to its source and
build.

`bag host install` copies the programs to `<home>/package/` (the bag home, `~/.bag` by default) and writes that path
into the host's files, so the wiring does not depend on npm's cache.

Source, specification and security policy: https://github.com/usebag/bag. Licence: Apache-2.0
(`dist/LICENSE`); third-party notices in `dist/THIRD-PARTY.md`.
