# Architecture and Port Map

This page gives newcomers a quick mental model of the current stable local setup.

## Basic login path

```text
                    Windows hosts file
                          |
                          | old PH hostnames -> 127.0.0.1
                          v
+------------------ Assault Fire PH client ------------------+
|                                                           |
| TCLS / launcher                                           |
|   |                                                       |
|   +---- VERSION ------------------------------> :9060     |
|   |                                                       |
|   +---- AUTH ---------------------------------> :8000     |
|   |        RSA-1024 + DH + AES                           |
|   |                                                       |
|   +---- DIR ----------------------------------> :9010     |
|            discovers local role/zone endpoints            |
|                                                           |
| TCLS                                                      |
|   +---- GetLoginInfo / selected-server state              |
|   +---- CreateProcessW(TGame.exe -q <uin>)                |
|   +---- TCLS_SHAREDMEMEMORY<child PID> ----------------+  |
|                                                       |   |
| TGame.exe <-------------------------------------------+   |
|   |                                                       |
|   +---- ROLE ---------------------------------> :65005    |
|   |                                                       |
|   +---- ZONE ---------------------------------> :65006    |
+-----------------------------------------------------------+
                          |
                          v
               server/assaultfire_server_v94.py
```

The client-side RSA public key and server-side private key must be a matching pair:

```text
TCLS\config\APClient.dat   <---- pair ---->   server\PRIVATE.PEM
       public key                                private key
```

## TCLS → TGame launch handoff

The launcher does more than spawn an executable. The verified PH build creates a shared-memory mapping named:

```text
TCLS_SHAREDMEMEMORY<decimal child PID>
```

and writes login/game-server handoff information for the new TGame process.

A validated runtime-only compatibility method can temporarily force `CREATE_SUSPENDED` at:

```text
TCLS.dll + 0x584E0
8B 55 18 52  ->  6A 04 90 90
```

Only use it when the original signature matches, and restore the original bytes immediately after TGame is created.

Full details: [Vital Launch Requirements](LAUNCH_REQUIREMENTS.md).

## Required TGame compatibility patch

The known PH TGame build can crash in a datetime conversion path.

Before launching the client, run:

```text
tools/patches/patch_tgame_datetime.py
```

The patch is runtime-only and verifies the known function signature before changing process memory.

Tracking: [Issue #3](https://github.com/armangido/af-emulator/issues/3).

## Optional PvE / The Altar path

The current research path adds two more components:

```text
                          +----------------------+
                          | Assault Fire client  |
                          +----------+-----------+
                                     |
                                     | UDP :65008
                                     v
                          +----------------------+
                          | bridge v5            |
                          | transparent relay    |
                          +----------+-----------+
                                     |
                                     | UDP :7777
                                     v
                          +----------------------+
                          | AFDEV listen server  |
                          | spawner v26          |
                          | SV-Maya_3_Main       |
                          +----------------------+
```

Files:

```text
tools/bridge/af_ds_udp_bridge_v5_actor_dump.py
tools/server_spawner/AFDevLoader_v26_pve_natural_loading_completion.py
```

This path is proven through map entry/player spawn, but the normal PvE round/enemy lifecycle remains incomplete.

## Port reference

| Port | Transport | Component | Notes |
|---:|---|---|---|
| 9060 | TCP | VERSION | Stable |
| 8000 | TCP | AUTH | Stable |
| 9010 | TCP | DIR | Stable |
| 65005 | TCP | ROLE | Stable baseline path |
| 65006 | TCP | ZONE | Stable baseline path |
| 65008 | UDP | PvE bridge | Optional PvE research |
| 7777 | UDP | AFDEV/UE3 | Optional PvE research |

## Source-of-truth rule

The project separates three levels of knowledge:

```text
VERIFIED
  observed in stock client / live test / recovered schema

PARTIAL
  useful implementation exists but complete retail behavior is not proven

EXPERIMENTAL
  research branch, inferred structure, or incomplete client verification
```

Only verified/reproducible behavior should be promoted into the stable public baseline.

See:

- [Project Status](STATUS.md)
- [Milestones](MILESTONES.md)
- [FAQ](FAQ.md)
- [Getting Started](GETTING_STARTED.md)
