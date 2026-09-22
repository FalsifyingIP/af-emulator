# Project Status

This page tracks the **public stable baseline only**.

Current public baseline: **v94**

Later experimental branches are intentionally excluded from `main` until they are reproducibly verified with the Assault Fire PH client.

## Status legend

| Mark | Meaning |
|---|---|
| ✅ Working | Reproducible in the current public baseline |
| 🟡 Partial | Implemented enough for testing/research, but not complete or not fully live-verified |
| 🔴 Broken / unavailable | Known not to work, intentionally excluded, or missing required protocol behavior |
| 🛠 Wanted | A feature we want contributors to help implement or verify |

## What currently works

| Area | Status | Notes |
|---|---:|---|
| VERSION service | ✅ | Local version-service response path is implemented. |
| AUTH handshake | ✅ | RSA/DH/AES authentication path used by the local client is implemented. |
| DIR/server discovery | ✅ | Local directory response and server endpoint discovery are implemented. |
| ROLE/ZONE connection foundation | ✅ | Stable branch can bring the existing local profile through the established login path. |
| Existing local player/profile state | ✅ | v94 has a known local player/profile path and persisted player state. |
| PlayerInfo / property delivery | ✅ | Stable player information and property/inventory messages used by v94 are implemented. |
| Shop foundation | ✅ | Stable shop/balance/purchase work from the pre-v95 branch is present. |
| Clan ID persistence | ✅ | v94 persists clan membership/ClanID and reflects it in PlayerInfo. |
| Clan name verification/create request shapes | ✅ | Known v94 request/response shapes are implemented for the stable branch. |

## Partial or research-grade features

| Area | Status | Current limitation |
|---|---:|---|
| Lobby browser | 🟡 | v94 exposes synthetic Survival rooms plus a client-created room slot. This is not a complete dynamic production-style lobby service. |
| Room create/list behavior | 🟡 | Foundation is present, but the complete multiplayer room lifecycle is not finished. |
| Friends | 🟡 | v94 includes A303-A30A foundation and a local test friend path; real two-client persisted social behavior belongs to later experimental work and is not part of the public baseline. |
| Private chat | 🟡 | v94 uses a LocalFriend echo/test path. Real friend-to-friend online/offline delivery is not part of this stable baseline. |
| Clans | 🟡 | Basic create/name/persistence behavior exists. Large nested clan detail/member responses were deliberately not guessed and still require verification. |
| Inventory/equipment | 🟡 | The stable profile/property path works, but not every item/equipment/UI edge case is verified. |
| Match allocation | 🟡 | Research exists, but complete retail-client match allocation and handoff are not in the stable v94 baseline. |
| TDR/protocol documentation | 🟡 | Many structures/opcodes are known, but documentation and exact field verification are incomplete. |

## Broken, unavailable, or intentionally excluded

| Area | Status | Why |
|---|---:|---|
| First-time account creation | 🔴 | Experimental v95+ work is intentionally excluded because it is not considered stable. |
| First-login nickname UI | 🔴 | Not part of v94 and not yet reproducibly verified for the public baseline. |
| New-account starter inventory/profile lifecycle | 🔴 | Depends on the experimental account-creation work and is intentionally excluded. |
| Real multi-account login lifecycle | 🔴 | Later experimental branches added this, but it is not part of stable v94. |
| Real two-client friends/private chat | 🔴 | Not included in v94; later work still needs proper stock-client validation before promotion. |
| Full clan UI/detail/member rendering | 🔴 | Nested ClanDetailedInfo/MemberInfo wire layouts are not fully verified. |
| PvE / The Altar complete gameplay lifecycle | 🔴 | The map can load and the player can spawn, but the PvE round/enemy lifecycle does not start correctly. See [non-working Altar sample issue #1](https://github.com/armangido/af-emulator/issues/1). |
| Survival enemy/round backend lifecycle | 🔴 | Not implemented as a complete public stable backend. |
| Dedicated-server allocation and UE3 handoff | 🔴 | Research exists in later branches, but stable end-to-end DS allocation/session lifecycle is not public yet. |
| Full match start → gameplay → result lifecycle | 🔴 | Not complete in v94. |
| Match history / ranking / player-card stock UI | 🔴 | Later backend experiments exist, but exact retail-client wire/UI integration is not part of v94. |
| Party/squad/team matchmaking | 🔴 | Not implemented in the stable public baseline. |
| Quick-match queue | 🔴 | Not implemented in v94. |
| Mail/inbox | 🔴 | Not implemented in the stable public baseline. |
| Achievements/missions full stock UI integration | 🔴 | Not implemented in v94. |
| Calendar/daily-login UI | 🔴 | Not part of v94. |

## What we want to implement

These are good contribution targets:

1. **Protocol documentation** — turn recovered command IDs and packet layouts into readable, reproducible documentation.
2. **Tests** — add unit tests and sanitized packet fixtures for VERSION, AUTH, DIR, ROLE, and ZONE behavior.
3. **Real room lifecycle** — replace synthetic/testing room behavior with a clean dynamic room model.
4. **Two-client social verification** — implement and verify friends, presence, friend requests, private chat, and reconnect behavior without depending on the broken first-login work.
5. **Clan completion** — recover and verify the nested clan detail/member structures used by the stock PH client.
6. **Existing-account persistence cleanup** — make stable existing-profile persistence easier to configure and test.
7. **PvE research** — document the exact loading → replication → round-start handoff for Survival/The Altar.
8. **Dedicated-server lifecycle** — document and implement the stock client allocation/handoff path once verified.
9. **Match lifecycle** — room start, loading, gameplay session, match completion, rewards/results, and clean teardown.
10. **Developer tooling** — packet decoders, protocol inspectors, sanitized logging, automated smoke tests, and reproducible test harnesses.

## Promotion rule

A feature should not move into the stable public baseline just because a backend implementation exists.

Before promotion to `main`, we want evidence that:

- the expected stock Assault Fire PH client request is observed;
- the response schema is based on verified protocol evidence rather than guessed nested structures;
- the feature does not regress the existing v94 login/profile path;
- secrets, copyrighted assets, and personal data are not included;
- reproduction steps are documented.

If you are researching an incomplete feature, opening an issue with logs, packet IDs, sanitized hex, or static-analysis findings is already a useful contribution.
