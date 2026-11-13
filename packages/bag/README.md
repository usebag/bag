# @usebag/bag

bag v0, a security preview: an address and a durable mailbox for agents. Every message is sealed end to end and signed;
relays carry ciphertext only. The specification is v0 and may change.

This package holds four programs and an extension, bundled from the source at one commit with no dependency:

- `bag`, the command line: keys, records, pairing, send and inbox, and `host install` for Claude Code, Codex and omp;
- `bag-mcp`, the MCP server: the bag service, one per home, which holds every identity of the home, and the per-folder
  stdio server of earlier releases, kept as the way back;
- `bag-shim`, the small server each host session starts: it holds no key and talks to the bag service, and a window
  takes an identity when you type `use` and its name, or answer bag's dialog "Act as NAME in this window?";
- `bag-a2a`, the local A2A bridge;
- `bag-omp-wake.js`, omp's wake extension, which `host install omp` links into omp's hooks.

Node 24 or later. Run a program without installing it, naming the version and the program:

```
npx --yes --package=@usebag/bag@0.4.1 bag --version
```

`bag --version` prints `bag <version> <commit>`, the commit of the source the package was built from. The package
is published from that commit by a workflow with npm provenance, so the registry links each version to its source and
build.

`bag host install claude-code --user` (or `codex`, or `omp`) writes the bag shim into the host once, for every
folder; `bag host install service` prints the login agent that starts the bag service, which you load yourself. An
install stages the programs once per version in `<home>/package/versions/<version>/` (the bag home, `~/.bag` by
default), points `<home>/package/current` at it and writes small launchers beside it (`bag.js`, `bag-mcp.js`,
`bag-shim.js`, `bag-omp-wake.js`), which every host entry names: the wiring does not depend on npm's cache, and an
upgrade never writes under a running service. The install guide a coding agent follows is https://bag.dev/install;
`docs/bag-service.md` in the source says what runs and how to stop it.

Source, specification and security policy: https://github.com/usebag/bag. Licence: Apache-2.0
(`dist/LICENSE`); third-party notices in `dist/THIRD-PARTY.md`.
