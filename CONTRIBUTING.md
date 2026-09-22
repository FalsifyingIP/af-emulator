# Contributing to Assault Fire Emulator

Thanks for helping with the project.

## What we want

Useful contributions include:

- protocol documentation
- packet decoders/encoders
- clean-room server implementation
- reproducible tests
- sanitized logs/fixtures
- bug fixes
- UE3/TDR research notes
- documentation improvements

## Before opening a pull request

1. Keep changes focused.
2. Explain what behavior you observed and how you verified it.
3. Remove secrets, account identifiers, IPs that should stay private, and unrelated personal data.
4. Do not include original game binaries or assets.
5. Do not paste large amounts of decompiled or disassembled proprietary code.
6. Prefer documenting behavior and data structures in your own words.
7. Add or update tests when practical.

## Protocol research reports

Please include:

- client version/build
- service or subsystem
- packet direction
- opcode/command
- sequence/correlation field if known
- packet size
- sanitized hex or decoded fields
- expected behavior
- observed behavior
- reproduction steps

## Branches

- `main`: stable, reviewable code and documentation
- feature/research branches: experimental work

Avoid committing unstable experiments directly to `main`.

## Pull requests

A good PR description explains:

- what changed
- why it changed
- how it was tested
- any protocol assumptions that are still uncertain

## Legal / redistribution

Only submit material you have the right to contribute.

Do not commit proprietary game executables, DLLs, maps, packages, textures, audio, leaked source code, private keys, credentials, or other restricted material.
