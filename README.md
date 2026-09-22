# Assault Fire Emulator

An unofficial, community-driven preservation and server-emulation project for **Assault Fire PH**.

> This project is not affiliated with, endorsed by, or sponsored by Tencent, Level Up! Games, or any original rights holder.

## Goal

The goal is to document and reimplement the network/backend behavior required to run the original Assault Fire PH client in an isolated/local environment for preservation, research, and interoperability.

This repository should contain **original project code and documentation only**. It must not contain copyrighted game binaries, proprietary game assets, leaked source code, private keys, credentials, or personal player data.

## Current research status

The project has working or substantially working research for:

- Version service
- Authentication handshake
- Directory/server discovery
- Login/account state
- Lobby and room-related backend work
- Shop/inventory/backend state work
- Friends/chat and clan research
- UE3 client/server reverse-engineering helpers
- TDR/protocol research
- PvE and dedicated-server handoff investigation

Areas still needing contributors and verification include:

- First-login / nickname flow
- Stock-client lobby and dynamic room behavior
- Friends/private-chat live verification
- Clan UI/protocol verification
- PvE round handoff and The Altar behavior
- Dedicated-server allocation/session lifecycle
- Additional TDR structure documentation
- Protocol cleanup, tests, and code organization

## Repository policy

### Allowed

- Clean-room server/emulator code written by contributors
- Protocol descriptions derived from observation/research
- Packet parsers/encoders
- Debugging and diagnostic tools written for this project
- Documentation
- Test fixtures that contain no proprietary content or secrets

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

The repository will be organized toward:

```text
server/      Emulator/server implementation
tools/       Original debugging, packet, and research utilities
docs/        Protocol and architecture documentation
tests/       Reproducible tests and sanitized fixtures
.github/     Contributor and issue templates
```

## Contributing

Contributions are welcome. Good starting points include protocol documentation, packet parsing, reproducible bug reports, tests, and investigation of open research issues.

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

## Preservation and interoperability

This project is intended for preservation, interoperability, education, and research around discontinued software. It does not provide the original game client or copyrighted game content.

## License

A project-code license has not yet been selected. Original game software and assets remain the property of their respective rights holders.
