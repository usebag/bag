# Third-party notices

This project (bag) is the lab's own work except where noted here.

## Litestream (the relay's image, deploy/relay/Dockerfile)

The binary of Litestream v0.5.17, by Ben Johnson and contributors, unmodified, with its licence at
/usr/share/doc/litestream/LICENSE in the image.
Source: https://github.com/benbjohnson/litestream
Licence: Apache License 2.0, https://www.apache.org/licenses/LICENSE-2.0

## Pairing wordlist (packages/edge/src/wordlist.json)

Derived from the EFF Short Wordlist (list #1, 1296 words) by the Electronic Frontier Foundation.
Source: https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt
Licence: Creative Commons Attribution 3.0 United States (CC BY 3.0 US),
https://creativecommons.org/licenses/by/3.0/us/

Modified from the original: the single hyphenated entry "yo-yo" was replaced with "yarn",
so that every entry is lowercase a-z (the pairing codec joins words with "-"). No other
entry was changed; the list still holds 1296 distinct words. This modification is indicated
as the licence requires.

## Agent Name Service registry material (deploy/discovery/ans/schema/)

Unmodified copies, in deploy/discovery/ans/schema/upstream/, of api-spec-v2.yaml, ans-1-registration.md,
ans-2-versioned-naming.md and LICENSE from the Agent Name Service reference registry, commit
f33c1aeba09ddc495395f5947eb1f11c79db73ae; registration-request.schema.json is converted from that OpenAPI file and
submit-ready.schema.json is derived from ANS-1 and ANS-2 (deploy/discovery/ans/schema/PROVENANCE.md says how). Not
part of the published cut.
Copyright 2025 GoDaddy Operating Company, LLC.
Source: https://github.com/agentnameservice/ans-registry
Licence: Apache License 2.0, https://www.apache.org/licenses/LICENSE-2.0 (upstream/LICENSE there)

## OASF record schema (deploy/discovery/oasf/schema/)

The Open Agentic Schema Framework (OASF) 1.1.0: the files under deploy/discovery/oasf/schema/source/ are unmodified
copies from the repository at tag v1.1.0, and record.1.1.0.schema.json is the JSON Schema the OASF schema server
serves for that release, unmodified (deploy/discovery/oasf/schema/PROVENANCE.md). The project's LICENSE.md and NOTICE
are copied beside them. Not part of the published cut.
Copyright OCSF a Series of LF Projects, LLC, and Copyright (c) 2025 Cisco and/or its affiliates; it includes the ICD
Schema developed by Symantec, a division of Broadcom (NOTICE there).
Source: https://github.com/agntcy/oasf
Licence: Apache License 2.0, https://www.apache.org/licenses/LICENSE-2.0 (LICENSE.md there)
