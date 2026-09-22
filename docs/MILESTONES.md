# Project Milestones

This roadmap describes the path from the current stable public baseline to a more complete Assault Fire PH local revival.

The rule for every milestone is simple:

> **Verified behavior moves forward. Guessed behavior stays experimental.**

## Milestone 0 — Public stable baseline ✅

**Status: complete**

Goal: publish a clean, reproducible starting point without the broken new-account branch.

Completed:

- [x] Stable v94 backend published
- [x] VERSION service
- [x] AUTH handshake
- [x] DIR/server discovery
- [x] Existing local profile/login path
- [x] Stable shop/inventory/profile foundation
- [x] Stable clan persistence foundation
- [x] Stable DS UDP bridge v5
- [x] Stable AFDEV PvE spawner v26
- [x] Local hosts redirect template/helper
- [x] RSA-1024 key generation helper
- [x] Beginner setup tutorial
- [x] MIT license
- [x] Working / partial / broken status documentation
- [x] The Altar non-working sample documented

## Milestone 1 — Reproducible local setup 🟡

**Status: active**

Goal: a new contributor can clone the repository and reproduce the known stable path with minimal manual reverse-engineering knowledge.

Tasks:

- [x] One-command RSA key generation
- [x] Automatic APClient.dat backup/install helper
- [x] Portable server key/log paths
- [x] Hosts setup helper
- [ ] Add a startup self-check for missing/incorrect files
- [ ] Add a port-conflict diagnostic
- [ ] Add a simple smoke-test script for VERSION/AUTH/DIR listeners
- [ ] Document the required client-side raw-PEM APClient/TCLS compatibility step more completely
- [ ] Validate the tutorial from a clean Windows install/folder

**Exit condition:** a clean setup can reach the existing local profile path by following only the repository documentation.

## Milestone 2 — Stable lobby, rooms, social, and clans 🟡

**Status: partial**

Goal: promote only live-verified multiplayer frontend/backend behavior into the stable branch.

Tasks:

- [ ] Replace synthetic room examples with a clean dynamic room lifecycle
- [ ] Verify room create / enter / leave / ready behavior with stock client
- [ ] Verify two-client friend request / accept / remove flow
- [ ] Verify two-client private chat
- [ ] Verify reconnect/offline-delivery behavior
- [ ] Complete stock clan detail/member structures
- [ ] Verify clan UI rendering and member updates
- [ ] Add protocol tests for verified commands

**Exit condition:** two local clients can use the normal stock lobby/social/clan flows without experimental account creation.

## Milestone 3 — The Altar playable end-to-end 🎯

**Status: current major research target**

Goal: turn the current "map loads and player spawns" state into a functioning PvE/Survival round.

Already proven:

- [x] PvE room path can reach The Altar
- [x] AFDEV PvE map loads
- [x] UE3 client/server traffic reaches the bridge
- [x] Client enters the map
- [x] Player spawns
- [x] HUD / weapon / movement are available

Still required:

- [ ] Identify the exact post-load handoff missing from the current run
- [ ] Verify loading-complete state on client and server
- [ ] Verify GameInfo / GameReplicationInfo / PlayerReplicationInfo state
- [ ] Trigger the stock authoritative round-start path naturally
- [ ] Verify AI/enemy wave initialization
- [ ] Verify objectives and round state progression
- [ ] Verify death/respawn behavior
- [ ] Verify round completion
- [ ] Verify result/reward handoff without faking client state
- [ ] Remove any temporary research-only patches no longer needed

See [The Altar non-working sample — Issue #1](https://github.com/armangido/af-emulator/issues/1).

**Exit condition:** The Altar starts a real stock PvE round, enemies/waves progress, and the round can finish normally.

## Milestone 4 — Dedicated server and full match lifecycle 🔴

**Status: planned/research**

Goal: recover and implement the stock PH dedicated-server allocation/handoff lifecycle.

Tasks:

- [ ] Verify the stock allocation request/response family
- [ ] Verify the exact client DS handoff message
- [ ] Implement stable DS registration/allocation
- [ ] Implement session-ready/start gating
- [ ] Verify player admission
- [ ] Verify disconnect/reconnect cleanup
- [ ] Verify match end and server/session teardown
- [ ] Add multi-client regression tests

**Exit condition:** a stock client can move from lobby → allocated server → gameplay → result → lobby through the normal verified protocol path.

## Milestone 5 — Preservation-quality release 🔴

**Status: planned**

Goal: make the emulator useful to other preservation researchers without requiring knowledge of this project's history.

Tasks:

- [ ] Split the monolithic v94 server into readable modules without changing behavior
- [ ] Add automated protocol/unit tests
- [ ] Add sanitized packet fixtures
- [ ] Add architecture and protocol reference docs
- [ ] Add configuration files instead of source-code constants
- [ ] Improve error messages and startup diagnostics
- [ ] Add contributor issue templates for protocol research
- [ ] Document reproducible client compatibility requirements
- [ ] Tag a stable release after regression testing

**Exit condition:** the stable project can be installed, understood, tested, and extended from the public repository alone.

## Not a milestone yet — first-time/new-account creation

The experimental first-time account/nickname work remains intentionally outside the public stable baseline.

It should not become a milestone until the stock PH client flow is reproducibly understood and can be implemented without destabilizing the existing working profile/login path.
