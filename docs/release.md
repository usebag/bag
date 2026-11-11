# Releasing bag

How bag is released: what a release is, how its version is chosen, when releases happen, every step from a change to a
published version, who approves what, how anyone can check a release, and how a bad one is undone. It is written for
the maintainers who make releases and for anyone who wants to check one.

Four workflows in `.github/workflows/` of this repository do the automated part, as a chain: `npm-publish.yml` stages
the version when the cut is merged, and `release.yml` takes over when that run ends, calling `relay-image.yml` and
`relay-binaries.yml` ("The release chain", below). All four use only `run` steps and this repository's own reusable
workflows, no third-party action, and pass their inputs to the shell only through the environment. A person approves
every step that makes something public: the merge of the cut, the approval on npm, and two clicks in the GitHub
environment `npm-release`.

## What a release is

A release is one commit on `main` of this repository, a public cut: one commit made from the source repository, whose
subject reads `bag public cut of <source commit>`. `main` can move on after it, since workflow files reach
`.github/workflows/` through pull requests of their own (step 3); the release stays that one commit. It carries:

- **a tag**, `vX.Y.Z`, on that commit;
- **a GitHub Release** for the tag. Its notes are the version's section of `CHANGELOG.md`, followed by the hashes to
  check: the npm tarball's sha256 and integrity, the relay image's digest and, once they are built, the relay binaries
  with a `SHA256SUMS` list ("Relay binaries", below);
- **the npm package** `@usebag/bag` at `X.Y.Z`, published from that commit. npm records the commit as `gitHead`, and
  the package carries a provenance statement naming this repository, the workflow and the commit;
- **the relay image** `ghcr.io/usebag/relay:vX.Y.Z`, the same image as `ghcr.io/usebag/relay:<commit>`, for
  linux/amd64 and linux/arm64.

No release is tagged yet. The first will be v0.1.2. 0.1.0 and 0.1.1 have no tag and get none ("v0.1.1", below). The
registry also lists `0.0.0-stage`, a placeholder npm made itself ("The first publish", below).

## Version numbers

bag follows semantic versioning, in 0.x while it is a security preview (`README.md`, "Status").

- **A patch** (0.1.1 to 0.1.2) carries fixes and documentation.
- **A minor** (0.1.x to 0.2.0) carries new features, or a change to the install guide that a user must act on.
- **The wire format has its own version**, the specification's (`spec/SPEC.md`), separate from the package's. A change
  to the wire format is a minor release, and its `CHANGELOG.md` section has a Security entry that says what changed
  and what an older installation does with it.
- **A number is never reused.** npm never takes a version twice, even after an unpublish, and a tag is never moved.

## When

On demand for now. Once the open call for security testing is out: one release a week, on Tuesday, and a fix release
whenever one is needed.

## The first publish

The steps below stage a version for a maintainer's approval. The package's first version could not go that way, and
what it took stays true for any package that does not exist yet:

- **npm attaches a trusted publisher only to a package that exists.** So 0.1.0 was published directly, on 2026-11-03,
  by the workflow of that time with a granular npm token held as a repository secret, limited to publishing in the
  package's scope and read only while npm answered that the package did not exist. The secret was deleted after that
  publish, and the workflow no longer has a token path.
- **npm made a placeholder.** At that first publish the registry created `0.0.0-stage`, at the same instant as the
  package: npm's own stub (`"stub": true`, a README and a `package.json`, no code, no `bin`, no `gitHead`). It installs
  only when asked for by that exact version, and it does not move `latest`. It stays; it may be deprecated, and it is
  never unpublished.
- **The trusted publisher stages only.** It was then set to this repository and `npm-publish.yml`, allowed to run
  `npm stage publish` and not `npm publish`. A new trusted publisher must complete a first successful publish within 2
  days or it expires, and is deleted and made again; 0.1.1's stage and approval validated this one on 2026-11-03.
- **A red run can still have published.** The run that published 0.1.0 read the registry 10 seconds later, got a 404,
  and ended red; the version answered about two and a half minutes after the publish. The registry is the record, not
  the run's colour: read it (step 6) before running again, since npm never takes a version twice. The staging workflow
  no longer reads the registry itself. After 0.1.1's approval the registry answered at once, and step 6 still waits.
- **0.1.1's provenance names another commit.** Its package bytes are the cut's, 3c343d65, as its `gitHead` says, but its
  provenance statement names 4c3dd680, the head of `main` when its run was started by hand, since npm's provenance
  records the head a run starts on. From the next version the workflow builds only the head it was started on, and the
  push of a rebase-merged cut is that head, so the two name the same commit.

## The steps

Each step names who does it. A step marked **gate** is a person's decision, and nothing goes on without it.

1. **The change.** Changes reach the source repository's `main` through reviewed, checked branches. The release's own
   change is made by one command there, `node scripts/release-bump.mjs X.Y.Z`, which lists every line it would change
   and writes nothing until it is given `--write` and `--who` with the name of who makes the change. It sets `version`
   in `packages/bag/package.json` (and the same line in `package-lock.json`), moves the `CHANGELOG.md` entries under a
   heading `## vX.Y.Z: YYYY-MM-DD`, which `release.yml` reads, and moves the pinned install lines that name a version
   (in `README.md`, `docs/partner-install.md`, `packages/mcp/README.md` and `packages/bag/README.md`). It also adds
   X.Y.Z to `BUILDS` in the telemetry Worker's build list (the Worker's source is not in this repository) and in
   `packages/edge/src/telemetry-schema.ts`, then raises `TELEMETRY_SCHEMA_COMMIT` to that commit. The telemetry Worker
   is deployed, a maintainer's own step with wrangler, before the cut's pull request is merged, since that merge stages
   the version (step 4) and the previous Worker refuses a report that carries the new version.
2. **The cut, gate.** The cut is built from the source repository at one commit, from an allow-list of paths, and its
   own checks run on it. A red from a run that crosses midnight UTC, in a test that reads the date, is recorded and the
   checks run again once after midnight; a second red stops the release. The pull request's commit is the cut's tree
   on top of this repository's `main`, keeping `main`'s `.github/`, which the cut never carries; the source
   repository's `scripts/cut-commit.sh` makes it, and refuses when any other file of `main` would vanish. Anything
   pinned to a source commit and a public commit (a client built from the source, which names the public commit) is
   checked with `scripts/cut-commit.sh --verify <public clone> <public commit> <cut directory> --source <source commit>`:
   it exits 0 only when the public commit holds exactly the cut's tree outside `.github/`. The cut is
   offered as one pull request on this repository, and a maintainer merges it with a rebase merge. That writes the commit anew on `main`, so the cut's sha
   on `main` is not the pull request's. Every later step takes the commit on `main`, the newest whose subject begins
   `bag public cut of `:

   ```sh
   gh api 'repos/usebag/bag/commits?sha=main&per_page=50' \
     --jq '[.[] | select(.commit.message | startswith("bag public cut of "))][0].sha'
   ```

3. **The workflow files, gate.** The cut never carries `.github/`, so a change to a workflow reaches
   `.github/workflows/` through a pull request of its own, from the source repository's copy, which a maintainer merges.
   `gh workflow run` answers HTTP 404 for a workflow that is not on `main`, so that pull request lands before any step
   that runs the workflow. A release that changes no workflow skips this step.
4. **Staging (the workflow).** A push to `main` that moves the version in `packages/bag/package.json` starts
   `npm-publish.yml`; the merge of the cut is that push, and it staged 0.1.2 that way on 2026-11-04 (run 41823544667).
   The push only stages: nothing is public until a maintainer
   approves on npmjs.com with two-factor authentication (step 5), and the trusted publisher's token can stage but
   cannot approve, so the gate is this repository's branch rules (`main` takes changes only through pull requests) and
   that approval, not the workflow run. The run builds and tests the package, packs it, and stages it on npm by trusted
   publishing (OIDC, no token) with provenance. It prints the tarball's sha256 in its pack step and, after checking
   that npm staged the tarball it packed, the line `staged @usebag/bag@X.Y.Z from <commit>, stage id <id>, <integrity>`.
   A push that leaves the version as it is, or names a version already on npm, ends green with nothing staged. The run
   builds only the head it was started on, since npm's provenance names that head, and it stops on any other commit.
   So it can be started by hand only while `main`'s head is the cut, here with the checks it needs first:

   ```sh
   V=X.Y.Z
   CUT="$(gh api 'repos/usebag/bag/commits?sha=main&per_page=50' \
     --jq '[.[] | select(.commit.message | startswith("bag public cut of "))][0].sha')"
   if [ "$(gh api repos/usebag/bag/commits/main --jq .sha)" != "$CUT" ]; then
     echo "STOP: main's head is not the cut, $CUT: the run builds only the head it starts on"
   elif [ "$(gh api "repos/usebag/bag/contents/packages/bag/package.json?ref=$CUT" -H 'Accept: application/vnd.github.raw' | jq -r .version)" != "$V" ]; then
     echo "STOP: the newest cut, $CUT, is not at $V"
   elif ! gh api repos/usebag/bag/contents/.github/workflows/npm-publish.yml >/dev/null 2>&1; then
     echo "STOP: npm-publish.yml is not on main: its pull request first (step 3)"
   elif curl -fsS -o /dev/null "https://registry.npmjs.org/@usebag%2fbag/$V" 2>/dev/null; then
     echo "STOP: @usebag/bag@$V is on npm already"
   else
     echo "staging @usebag/bag@$V from $CUT"
     gh workflow run npm-publish.yml --repo usebag/bag -f commit="$CUT"
   fi
   ```

   A version staged and not yet approved is not on the registry, so these checks do not see it; npm refuses to stage
   it a second time.

   A staging run started by hand does not start `release.yml`. Its `workflow_run` path takes only staging runs that a
   push started, so every job of the release run it triggers is skipped, `staged` first. Step 5 is then started by
   hand, with the line that step 8 gives for a release run that is gone (0.2.2 went this way on 2026-11-09):

   ```sh
   gh workflow run release.yml --repo usebag/bag -f version=X.Y.Z -f commit=<the cut commit>
   ```
5. **Approval, gate, then the first click.** When the staging run ends green, `release.yml` starts by itself. Its first
   job, `staged`, reads the version, the commit, the stage id and the tarball's sha256 from the staging run's log,
   checks that the commit is a public cut on `main` at that version, and prints what the maintainer does next, also on
   the run's summary page. A staging run that staged nothing ends the release run there, green. The maintainer then
   approves the staged version on npmjs.com: the Staged Packages tab, Approve, then two-factor authentication. The
   workflow's own credential can stage but cannot approve; in a terminal the same is `npm stage approve <stage id>`,
   with npm 11.15.0 or later. Then the maintainer approves the release run's job `approval`, which waits in the
   environment `npm-release` and does nothing else: on the run's page, Review deployments, `npm-release`, Approve and
   deploy. GitHub holds a run up to 30 days for that click. If `staged` stops instead, for example because the pushed
   commit is not a public cut, the staged version is rejected on npmjs.com ("When something is wrong").
6. **npm, read back (the workflow).** The job `npm` waits for the registry, up to 80 reads 15 seconds apart (20
   minutes), then makes the five checks below; latest must be the version. When the registry does not answer in time,
   because the npm approval was not given, the job says so and fails, and "Re-run failed jobs" on the run's page goes
   on from there once it is given. Anyone can make the same checks by hand, here with 20 reads; `SHA` is the `sha256`
   line of the staging run's pack step:

   ```sh
   V=X.Y.Z; CUT=<the cut commit>; SHA=<the sha256 of the staging run>
   for i in $(seq 1 20); do curl -fsS -o v.json "https://registry.npmjs.org/@usebag%2fbag/$V" 2>/dev/null && break; sleep 15; done
   curl -fsS -o p.tgz "$(jq -r .dist.tarball v.json)"
   curl -fsS -o a.json "$(jq -r .dist.attestations.url v.json)"
   [ "$(jq -r .gitHead v.json)" = "$CUT" ] && echo "gitHead: the cut"
   [ "$(jq -r '.attestations[] | select(.predicateType == "https://slsa.dev/provenance/v1") | .bundle.dsseEnvelope.payload' a.json | base64 -d | jq -r '.predicate.buildDefinition.resolvedDependencies[] | select(.uri | startswith("git+https://github.com/usebag/bag@")) | .digest.gitCommit')" = "$CUT" ] && echo "provenance: the cut"
   [ "sha512-$(openssl dgst -sha512 -binary p.tgz | openssl base64 -A)" = "$(jq -r .dist.integrity v.json)" ] && echo "integrity: matches"
   [ "$(shasum -a 256 p.tgz | cut -c1-64)" = "$SHA" ] && echo "sha256: the staging run's"
   [ "$(curl -fsS https://registry.npmjs.org/-/package/@usebag%2fbag/dist-tags | jq -r .latest)" = "$V" ] && echo "latest: $V"
   ```

   Five lines; a missing line stops the release. The provenance line reads the commit the SLSA statement names as its
   source, not only that a statement exists.
7. **The relay image (the workflow).** The job `image` calls `relay-image.yml` with the commit. It builds
   `ghcr.io/usebag/relay:<commit>` for linux/amd64 and linux/arm64, each on its own native runner, with provenance and
   an SBOM; an image of the commit that exists with both platforms is not built again. By hand, the same is:

   ```sh
   gh workflow run relay-image.yml --repo usebag/bag -f commit=<the cut commit>
   ```

8. **The tag, the Release and the binaries (the workflow).** The job `release` first finds what an earlier attempt
   left: the tag `vX.Y.Z` must be absent or on the commit, and the image tag `vX.Y.Z` absent or on the image's digest,
   or the job stops, since a tag is never moved. It then tags the image `vX.Y.Z` (the same digest, no rebuild), tags
   the commit `vX.Y.Z`, and makes the Release, skipping with a line each of the three that exists already. The notes
   are the `## vX.Y.Z` section of `CHANGELOG.md`, read at the commit, or on `main` for a release tagged after the fact,
   followed by the hashes that step 6 checked and the image's digest. Then the job `binaries` calls
   `relay-binaries.yml` with the commit and the version, when the commit holds `crates/ac-relay/THIRD-PARTY-RUST.md`
   ("Relay binaries", below). For a version whose release run is gone, the whole chain runs again from its first job
   by hand, and waits again for the click in `npm-release`:

   ```sh
   gh workflow run release.yml --repo usebag/bag -f version=X.Y.Z -f commit=<the cut commit>
   ```

9. **The install guide, gate, then the second click.** The guide at https://bag.dev/install pins three values: the
   release commit, the version, and the tarball's sha256, which step 6 checked against the registry's tarball. The
   maintainers set the three in their own infrastructure's configuration, keeping the previous values for a rollback,
   then apply it: one change, the guide's Worker. No workflow of this repository can make that change ("The install
   guide", below). The job `site` reads https://bag.dev/install once a minute for up to 30 minutes, printing at each
   read what the page names and lacks, and goes on at the first read that names the new version, commit and sha256 and
   holds no unfilled `{{`. So the apply and the second click can come in either order, within 30 minutes of each other:
   1. Apply the guide's Worker, and check that https://bag.dev/install names the three values.
   2. Approve the job `site`, the second click in `npm-release`: Review deployments, `npm-release`, Approve and deploy.
   3. If the 30 minutes ran out first, `site` stops, naming what is missing: apply, then "Re-run failed jobs" on the
      release run's page. 0.2.2 (2026-11-09) and 0.2.3 (2026-11-10) went that way, with a `site` that read the page
      only once.
10. **The website, gate.** The job `site` then sends a `repository_dispatch`, the event `bag-release` with the
    version, the cut and the sha256, to the website's repository. The website's own workflow checks the release again,
    reads the guide as bag.dev serves it, and opens a pull request that moves the version mentions on bag.dev; a
    maintainer merges it, and the merge deploys the website, ending with a check of the live site. That pull request is
    opened by the GitHub Actions bot, so its own checks (`ci` and `preview`) do not run until a maintainer approves the
    workflow runs on the pull request's page; until then they show "action required", and the merge waits for them. A dispatch that got
    as far as the website's branch for the version is not sent twice. Without the setup below, the job skips the
    dispatch with a line, and the website's change is made by hand; its deploy can also be started by hand:

    ```sh
    gh workflow run deploy.yml --repo <the website's repository>
    ```

11. **Read-backs.** The Release page shows the hashes of step 8, the npm package and the guide name the same commit,
    and the image tag `vX.Y.Z` has the digest in the notes.

## Who approves what

| Gate | Who | What it guards |
|---|---|---|
| the cut's pull request | a maintainer merges it | what enters this repository's `main`, and the staging it starts |
| a workflow file's pull request | a maintainer merges it | what the workflows run |
| the npm approval | a maintainer, with two-factor authentication | what becomes public on npm |
| the first click, the job `approval` in `npm-release` | the maintainer, after the npm approval | the image, the tags, the Release and the binaries |
| the install guide's apply | a maintainer | what https://bag.dev/install tells an agent to install |
| the second click, the job `site` in `npm-release` | the maintainer, after the guide's apply | that the website's repository is told |
| the website's pull request | a maintainer merges it | what bag.dev says; the merge deploys it |

Steps 4 to 8 and the dispatch of step 10 are workflows. Step 4 starts itself on the push of the cut, and `release.yml`
starts itself when step 4's run ends. None of them publishes anything a gate has not passed: a staged version is not
public until step 5, nothing after the npm approval runs before the first click, and the website hears of the release
only after the second.

## The release chain

`release.yml` runs these jobs, each after the one before it; the binaries and the website's dispatch both follow the
Release and do not wait for each other.

| Job | What it does | Writes |
|---|---|---|
| `staged` | the version, the commit, the stage id, the integrity and the sha256 from the staging run's log; the commit is a public cut on `main` at the version; what the maintainer does next | nothing |
| `approval` | waits in `npm-release` for the first click | nothing |
| `npm` | waits for the registry, then step 6's five checks | nothing |
| `image` | `relay-image.yml` with the commit (step 7) | `ghcr.io/usebag/relay:<commit>` |
| `release` | the image tag, the tag and the Release (step 8) | `relay:vX.Y.Z`, the tag `vX.Y.Z`, the Release |
| `binaries` | `relay-binaries.yml` with the commit and the version, when the commit holds `crates/ac-relay/THIRD-PARTY-RUST.md` | the archives, their signatures and `SHA256SUMS` on the Release |
| `site` | waits in `npm-release` for the second click; checks the served guide (step 9); tells the website (step 10) | a `repository_dispatch` to the website's repository |

It starts on the end of a staging run that a push started, and it can be started by hand with a version and a commit
(step 8's command), which runs it from `staged` again. Every job can run again: "Re-run failed jobs" on the run's page
repeats a failed job and the jobs after it, and a job that finds what an earlier attempt made, as it should be, skips
it with a line. It stops instead when it finds it otherwise, such as a tag on another commit, and never moves a tag.
A click that is not given within 30 days ends the run; the chain is then started by hand.

## One-time setup

Done once by a maintainer with admin rights on this repository, before the first release that runs the chain. Until
the environment exists with its reviewer, the chain does not wait for a click: GitHub creates a missing environment
without protection rules, and the job `npm` then fails after 20 minutes because the npm approval has not happened.

1. **The environment `npm-release`.** Settings, Environments, New environment, `npm-release`, Configure environment.
   Tick Required reviewers and enter the maintainer who approves on npm (up to six people or teams; one approval
   suffices). Leave "Prevent self-review" unticked: the push that starts the chain is the maintainer's own merge of
   the cut, and with it ticked that maintainer could not approve. Under Deployment branches and tags, choose Selected
   branches and tags and add `main`. Save protection rules. The same with `gh`, run by that maintainer (the first line
   reads their own user id), which needs the Administration permission:

   ```sh
   ID="$(gh api user --jq .id)"
   printf '{"reviewers": [{"type": "User", "id": %s}], "prevent_self_review": false, "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}' "$ID" |
     gh api --method PUT repos/usebag/bag/environments/npm-release --input -
   gh api --method POST repos/usebag/bag/environments/npm-release/deployment-branch-policies -f name=main -f type=branch
   ```

2. **The variable `SITE_REPOSITORY`**, the website's repository as `owner/name`:
   `gh variable set SITE_REPOSITORY --repo usebag/bag`, which asks for the value.
3. **The secret `SITE_DISPATCH_TOKEN`.** A fine-grained personal access token: resource owner `usebag`, only the
   website's repository, the repository permission Contents: Read and write (sending a `repository_dispatch` needs
   Contents write; Metadata: Read comes with it), and an expiry date. Nothing else: the website's workflow opens its
   pull request with its own token. Then `gh secret set SITE_DISPATCH_TOKEN --repo usebag/bag`, which asks for the
   value.
4. **The website's side.** Its release workflow, which answers the `bag-release` dispatch, and its deploy on a merge to
   its `main`, are merged in the website's repository.
5. **The workflow files.** The four workflows reach `.github/workflows/` through their own pull request (step 3).
6. **Not now:** the secret `CLOUDFLARE_INSTALL_TOKEN` would come only with option (a) of "The install guide",
   below, which is not taken.

## The install guide

The guide at https://bag.dev/install is served by a Worker that the maintainers' infrastructure configuration defines
and applies from a maintainer's machine; its state is kept there too, so no workflow of this repository can change
it. Two ways to run step 9 were weighed, and (b) was chosen on 2026-11-04:

- **(a) The Worker moves into this repository.** Its script becomes `deploy/install/worker.js` here, public. A job
  `deploy-guide` in `release.yml`, after `release`, fills the guide's nine values and uploads the Worker with wrangler,
  using a Cloudflare API token held as the secret `CLOUDFLARE_INSTALL_TOKEN`; `site` then follows it without a click
  of its own. The infrastructure configuration keeps the routes and the DNS records. The move takes one removal of
  the Worker from that configuration's state and one apply, a maintainer's. The cost: Cloudflare's Workers Scripts
  permission applies to a whole account (developers.cloudflare.com/fundamentals/api/reference/permissions/ names no
  narrower scope), so the token could replace every Worker of that account, the guide's among them, and it would sit
  in this public repository's Actions. Held as a secret of the environment `npm-release`, a job reads it only after a
  click, and only on `main`.
- **(b) The apply stays a maintainer's one command,** run after the job `release` with the three values it printed,
  followed by the second click. This is how it runs.

Why (b): the guide is what an agent trusts to install bag, and (b) keeps the only credential that can change it off
GitHub, at the cost of one command per release; the job `site` stops when the guide was not applied. (a) is weighed
again when releases become weekly, with the token held as a secret of the environment `npm-release`.

## Checking a release yourself

- **The tag:** `git ls-remote https://github.com/usebag/bag refs/tags/vX.Y.Z` prints the release commit.
- **npm:** `npm view @usebag/bag@X.Y.Z gitHead dist.integrity` prints the same commit and the integrity in the
  Release notes. The package page on npmjs.com shows its provenance: this repository, `npm-publish.yml`, the commit.
  The version list (`npm view @usebag/bag versions`) also holds npm's placeholder `0.0.0-stage`, which is no release
  ("The first publish", above).
- **The tarball:** `npm pack @usebag/bag@X.Y.Z`, then `shasum -a 256 usebag-bag-X.Y.Z.tgz`; the sha256 is the one in
  the Release notes, and the one the install guide checks a copied package file against.
- **The image:** `docker buildx imagetools inspect ghcr.io/usebag/relay:vX.Y.Z` prints the digest in the notes.

## When something is wrong

- **npm.** A published version is never unpublished, and its number is never used again. It is deprecated, with the
  reason and the version to use (`npm deprecate @usebag/bag@X.Y.Z "<reason>"`, a maintainer with two-factor
  authentication), `latest` goes back to the version before it (`npm dist-tag add @usebag/bag@<that version> latest`),
  and the next patch follows. Before the approval, a staged version is rejected instead, on npmjs.com or with
  `npm stage reject <stage id>` (npm 11.15.0 or later), and nothing was public.
- **The tag and the Release.** They are not moved or deleted. The Release notes say what is wrong and name the next
  patch.
- **The relay image.** A version tag is not moved; the next patch gets its own.
- **The install guide.** It goes back to the previous release's values, kept for this, and is applied and read
  back.
- **The website.** The change is reverted, and the merge of the revert deploys it.
- **The release run.** A job waiting for a click is turned down with Reject (Review deployments): the run fails there
  and nothing after it runs. A run that stopped is continued with "Re-run failed jobs" once the cause is fixed; a run
  that is gone is started again by hand (step 8). A version staged from a commit that `staged` refuses is rejected on
  npm.

## v0.1.1: not tagged

0.1.1 was published on npm, served by the install guide and named by the website on 2026-11-03 and 2026-11-04, before
this process was written down: steps 4 to 6, 9 and 10 above are done for it. It has no relay image, no tag and no
Release. Its package bytes are its cut's, 3c343d65, but its provenance statement names 4c3dd680, the head of `main`
when its run was started ("The first publish", above). Step 8 checks the provenance's commit, so `release.yml` stops for
0.1.1 as it stands. On 2026-11-04 it was decided that v0.1.1 gets no tag and no Release, and that v0.1.2 is the first
tagged release. These were its next steps before that, on its cut, `3c343d65a39481aee1b0c53010736cd49ef1f90c`:

0. **The relay image (a maintainer; it publishes an image).**

   ```sh
   gh workflow run relay-image.yml --repo usebag/bag -f commit=3c343d65a39481aee1b0c53010736cd49ef1f90c
   docker buildx imagetools inspect ghcr.io/usebag/relay:3c343d65a39481aee1b0c53010736cd49ef1f90c
   ```

   The second command prints the image's digest once the run is done.
1. **The notes and the workflow.** `CHANGELOG.md` on `main` has the section `## v0.1.1: 2026-11-03`. The cut 3c343d65
   came before the heading convention, so `release.yml` reads the section from `main`. `release.yml` is on `main`
   through its own pull request (step 3).
2. **The tag and the Release (a maintainer starts it).**

   ```sh
   gh workflow run release.yml --repo usebag/bag -f version=0.1.1 -f commit=3c343d65a39481aee1b0c53010736cd49ef1f90c
   ```

3. **Read-back.** `git ls-remote https://github.com/usebag/bag refs/tags/v0.1.1` prints the cut. The Release notes give
   the npm tarball's sha256 as `32fc7a281aef764c874652d85341aeefb8567af7b497e05a113713dc25248b56`.

## Relay binaries (not built yet)

`relay-binaries.yml` builds the reference relay, `ac-relay`, from the release commit and, given the version, uploads
what it makes to the Release `vX.Y.Z` of step 8. The release chain calls it once the release commit holds
`crates/ac-relay/THIRD-PARTY-RUST.md`, the notices of the Rust crates compiled into the binary, which every archive
carries; a release without that file has no binaries. Nothing below has run yet. A target whose archive and signature
are on the Release already is not built again, and neither is `SHA256SUMS`.

- **Linux, static.** `x86_64-unknown-linux-musl` on `ubuntu-24.04` and `aarch64-unknown-linux-musl` on
  `ubuntu-24.04-arm`, each built natively. They link musl statically, so one binary runs on any Linux of its
  architecture, old distributions included. The relay compiles C (SQLite, bundled by rusqlite, and parts of ring), so
  the runner installs Ubuntu's `musl-tools` for a musl C compiler.
- **macOS.** `aarch64-apple-darwin` on `macos-15` (Apple silicon).
- **The build.** The toolchain pinned in `rust-toolchain.toml`, and
  `cargo build --release --locked -p ac-relay --target <target>` from the release commit.
- **The files.** One archive per target, `ac-relay-vX.Y.Z-<target>.tar.gz`, holding the binary, `LICENSE`,
  `THIRD-PARTY.md` and `THIRD-PARTY-RUST.md`, and `SHA256SUMS`, which lists the three archives.
- **The signatures.** Each archive and `SHA256SUMS` are signed with cosign, keyless. cosign is a pinned release,
  downloaded in a run step and checked against a sha256 written in the workflow, as `npm-publish.yml` checks Node; no
  third-party action. The signature is bound to the job's GitHub identity (its OIDC token), which names
  `relay-binaries.yml` also when `release.yml` calls it, recorded in Sigstore's public transparency log, and saved
  beside each file as `<file>.sigstore.json`. To check one archive:

  ```sh
  cosign verify-blob ac-relay-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz \
    --bundle ac-relay-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz.sigstore.json \
    --certificate-identity https://github.com/usebag/bag/.github/workflows/relay-binaries.yml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  sha256sum -c --ignore-missing SHA256SUMS
  ```

- **macOS, unsigned for the preview.** The macOS binary is not signed with an Apple Developer ID. A file downloaded in
  a browser is quarantined, and Gatekeeper then blocks an unsigned binary; one fetched with `curl` is not quarantined.
  After checking its sha256 and its cosign signature, remove the quarantine with
  `xattr -d com.apple.quarantine ac-relay`.
- **Apple signing, a later decision.** Signing and notarising with a Developer ID needs the Apple Developer Program, 99
  USD per membership year (developer.apple.com/programs/enroll). Only the program's Account Holder can generate the
  Developer ID certificate, and the certificate would be held as a secret of the workflow.

## The checklist

| # | Step | Who | Command or check |
|---|---|---|---|
| 1 | version, lock line, `## vX.Y.Z: YYYY-MM-DD` section, pinned install lines, telemetry `BUILDS` | maintainer | `node scripts/release-bump.mjs X.Y.Z` in the source repository, reviewed; the telemetry Worker deployed before the cut's merge |
| 2 | the cut, as one pull request, rebase-merged | maintainer merges | the cut's own checks pass; the cut commit is the newest `bag public cut of ` on `main` |
| 3 | a changed workflow file, as its own pull request | maintainer merges | `gh workflow run` finds the workflow on `main` |
| 4 | stage on npm | `npm-publish.yml`, on the merge, or started by hand | the run prints `staged @usebag/bag@X.Y.Z from <commit>, ...` and the sha256 |
| 5 | approve, then the first click | maintainer, 2FA; then `npm-release` | npmjs.com, Staged Packages, Approve; the release run's job `approval` |
| 6 | npm read-back | the release run's job `npm`, or anyone | step 6's five lines |
| 7 | relay image | the job `image` | `ghcr.io/usebag/relay:<commit>` exists for both platforms |
| 8 | tag, Release, binaries | the jobs `release` and `binaries` | the Release `vX.Y.Z` on the commit, with the hashes |
| 9 | install guide, then the second click | maintainer applies; then `npm-release` | https://bag.dev/install names the new commit, version and sha256; the job `site` |
| 10 | website | the job `site`, then a maintainer merges the website's pull request | bag.dev names the new version |
| 11 | read-backs | anyone | "Checking a release yourself", above |
