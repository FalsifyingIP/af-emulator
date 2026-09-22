# Stable PvE Bridge and Server Spawner

This repository includes the two known-good local tools used to reach the Assault Fire PH PvE map during preservation testing.

They are published because the components themselves are reproducible and useful to contributors.

> These tools do **not** mean The Altar is fully working. The current failure is later in the post-load PvE round/gameplay lifecycle.

## Included tools

### 1. Stable DS UDP bridge — v5

File:

```text
tools/bridge/af_ds_udp_bridge_v5_actor_dump.py
```

Purpose:

```text
Assault Fire client
    UDP :65008
        |
        | transparent AF wire packets
        v
v5 bridge
        |
        | transparent AF wire packets
        v
AFDEV / UE3 listen server
    UDP :7777
```

The bridge:

- listens on UDP port **65008**;
- forwards traffic to the local AFDEV/UE3 server on **127.0.0.1:7777**;
- relays packets byte-for-byte unchanged;
- has diagnostic decoding for the known local test state;
- records useful early actor-channel payloads to `af_actor_payloads.log`;
- includes Windows UDP reset handling used during the known-good tests.

Run it with:

```powershell
python .\tools\bridge\af_ds_udp_bridge_v5_actor_dump.py
```

The bridge currently binds to `0.0.0.0:65008` because that is the configuration used by the known-good test version. Use it only on a trusted/local test network and do not expose it directly to the public internet.

## 2. Stable AFDEV PvE server spawner — v26

File:

```text
tools/server_spawner/AFDevLoader_v26_pve_natural_loading_completion.py
```

This is the known-good AFDEV launcher/spawner used with the v5 bridge.

It starts a locally supplied, validated `TGame_AFDEV.exe`, performs the established offline/local runtime setup, and loads the PvE listen-server map path used during our successful map-entry tests.

The expected clean AFDEV executable SHA-256 is checked by the script:

```text
b4273f2658ca94eebc559a997fdfcd02d51e77ce75b892250c1db7fb80c70b51
```

The executable itself is **not distributed by this repository**.

### Configure the game directory

Either set:

```powershell
$env:AF_GAME_DIR = "D:\YourAssaultFireFolder\Binaries\Win32"
```

or provide the directory directly:

```powershell
python .\tools\server_spawner\AFDevLoader_v26_pve_natural_loading_completion.py --game-dir "D:\YourAssaultFireFolder\Binaries\Win32"
```

The default map is:

```text
SV-Maya_3_Main
```

You can explicitly select it with:

```powershell
python .\tools\server_spawner\AFDevLoader_v26_pve_natural_loading_completion.py --game-dir "D:\YourAssaultFireFolder\Binaries\Win32" --map SV-Maya_3_Main
```

## Recommended local test order

For a PvE research session:

```text
1. Start the emulator/backend needed for the test.
2. Start AFDevLoader v26.
3. Confirm the AFDEV listen server reaches its loaded-map state / UDP 7777.
4. Start the v5 bridge.
5. Confirm the bridge is waiting on UDP 65008.
6. Launch the Assault Fire PH client through your local test setup.
7. Reproduce The Altar.
8. Collect the smallest useful bridge/server/backend logs around the failure.
```

Depending on the backend branch being researched, the client must be handed the bridge endpoint rather than the raw AFDEV port.

## What is proven

The stable bridge/spawner path has demonstrated:

- AFDEV PvE map loading;
- a functioning local UE3 listen-server endpoint;
- transparent two-way client/server datagram relay;
- UE3 Challenge/Netspeed/network progression;
- client travel into **The Altar**;
- player spawn into the map with HUD/weapon/movement available.

## What is still broken

The known non-working sample reaches the map, but the expected PvE round lifecycle does not proceed normally.

Current research remains focused on:

- post-load PvE initialization;
- client loading-complete / authoritative handoff;
- GameInfo / GameReplicationInfo / PlayerReplicationInfo state;
- round-start state;
- AI/enemy wave initialization;
- objective and completion flow.

See [Project Status](STATUS.md) and [The Altar sample issue](https://github.com/armangido/af-emulator/issues/1).

## Why v5 and v26 are the public versions

Later bridge experiments exist, including versions that changed login/options or tested causal packet modifications. Those are intentionally not being presented as the stable public bridge.

Likewise, later AFDEV server-mode and PvE probes are research experiments rather than replacements for the known-good v26 listen-server launcher.

The rule for `main` remains: publish the smallest reproducible known-good component, and keep experimental variants separate until verified.
