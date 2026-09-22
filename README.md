# Assault Fire Emulator

An unofficial, community-driven preservation and server-emulation project for **Assault Fire PH**.

> This project is not affiliated with, endorsed by, or sponsored by Tencent, Level Up! Games, or any original rights holder.

## Start here

New to the project?

- **[Friendly setup tutorial](docs/GETTING_STARTED.md)** — clone, install, configure the local key, run v94, test the client, and prepare a useful bug report.
- **[Working / broken / planned status](docs/STATUS.md)** — shows what currently works, what is only partial, what is broken/unavailable, and what contributors can help implement.
- **[Contributing guide](CONTRIBUTING.md)** — rules for safe protocol research, pull requests, and sanitized evidence.
- **[Stable PvE bridge + server spawner](docs/PVE_BRIDGE_AND_SPAWNER.md)** — known-good v5 UDP bridge and v26 AFDEV listen-server launcher used for The Altar research.

## Current public baseline

The current public baseline is **v94**.

This is intentionally the last known stable branch before the experimental first-login / new-account creation work. Those experimental account-creation changes are **not included in this repository at this time**.

The stable baseline currently contains the project's working/reproducible implementation for:

- VERSION service
- AUTH handshake
- DIR/server discovery
- existing local profile / zone login path
- player information and inventory/property handling used by the stable branch
- shop/backend work from the stable branch
- lobby/room foundation
- friends/chat foundation
- clan foundation and persisted ClanID work

The server source is currently kept as a versioned baseline:

```text
server/assaultfire_server_v94.py
```

Later experimental branches are being kept out of `main` until their behavior is verified.

## Goal

The goal is to document and reimplement the network/backend behavior required to run the original Assault Fire PH client in an isolated/local environment for preservation, research, and interoperability.

This repository contains **original project code and documentation only**. It must not contain copyrighted game binaries, proprietary game assets, leaked source code, private keys, credentials, or personal player data.

## Running the stable baseline

Python 3.12 is recommended.

Install the Python dependency:

```bash
pip install -r requirements.txt
```

The server expects a locally supplied RSA private key. The key itself must **never** be committed.

By default the stable server looks for:

```text
server/PRIVATE.PEM
```

You can instead set:

```text
AF_PRIVATE_KEY=<path to your local PRIVATE.PEM>
AF_LOG_PATH=<optional server log path>
AF_X32DBG_LOG=<optional x32dbg crypto log path>
```

Then run:

```bash
python server/assaultfire_server_v94.py
```

The current baseline is designed around local/isolated preservation testing.

## Repository policy

### Allowed

- Clean-room server/emulator code written by contributors
- Protocol descriptions derived from observation/research
- Packet parsers/encoders
- Debugging and diagnostic tools written for this project
- Documentation
- Sanitized test fixtures containing no proprietary content or secrets

### Do not commit

- `TGame.exe`, `TCLS.dll`, or other original game binaries
- Original `.upk`, `.udk`, audio, textures, maps, or other game assets
- Private keys or certificates
- Account credentials
- Raw player-state files containing personal information
- Full memory dumps
- Decompiled/disassembled proprietary code copied verbatim
- Files you do not have permission to redistribute

Users must obtain any required original game client files independently and lawfully.

## Project structure

```text
server/      Stable emulator/server implementation
tools/       Original debugging, packet, and research utilities
docs/        Protocol and architecture documentation
tests/       Reproducible tests and sanitized fixtures
.github/     Contributor and issue templates
```

For now, only verified/stable material is being promoted into the public baseline.

## Contributing

Contributions are welcome. Good contributions include protocol documentation, packet parsing, reproducible bug reports, tests, and fixes against the stable baseline.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting code or research.

When reporting protocol behavior, include reproducible evidence where possible:

- client version
- packet direction
- command/opcode
- packet length
- sanitized hex or decoded fields
- expected behavior
- observed behavior
- relevant logs with secrets/private data removed

Please do not submit speculative account-creation/new-account changes to `main` until that flow is reproducibly verified.

## Preservation and interoperability

This project is intended for preservation, interoperability, education, and research around discontinued software. It does not provide the original game client or copyrighted game content.

## License

The original code and documentation in this repository are licensed under the [MIT License](LICENSE).

This license applies only to material created for the `af-emulator` project. It does **not** grant rights to Assault Fire, the original game client, executables, DLLs, maps, packages, artwork, audio, trademarks, or any other third-party material. Those remain the property of their respective rights holders.
