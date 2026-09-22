# Friendly Getting Started Guide

Welcome! You do **not** need to understand the entire Assault Fire protocol before helping with this project.

The public repository starts from the stable **v94** emulator baseline. The goal of this guide is to get that baseline running locally and show you how to contribute without accidentally committing private keys or original game files.

## 1. What you need

You need:

- Windows 10/11
- Python 3.12 recommended
- Git
- obtain a copy of 1.0.0.24 Assault Fire Game files
- a local RSA private key used by your own emulator setup

The repository does **not** distribute the original client, game assets, DLLs, maps, packages, or private keys.

## 2. Clone the repository

Open PowerShell:

```powershell
git clone https://github.com/armangido/af-emulator.git
cd af-emulator
```

If you only want to test and not contribute yet, downloading the repository as a ZIP is also fine.

## 3. Create a Python environment

A virtual environment keeps the emulator dependencies separate from the rest of your PC.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, you can still call the environment directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## 4. Supply your local private key

The server needs the RSA private key from **your own local emulator setup**.

The easiest layout is:

```text
af-emulator/
└── server/
    ├── assaultfire_server_v94.py
    └── PRIVATE.PEM
```

`PRIVATE.PEM` is ignored by Git and must never be committed.

You can also keep the key somewhere else:

```powershell
$env:AF_PRIVATE_KEY = "D:\your-private-folder\PRIVATE.PEM"
```

Optional paths:

```powershell
$env:AF_LOG_PATH = "D:\af-logs\server.log"
$env:AF_X32DBG_LOG = "D:\af-logs\x32dbg.log"
```

## 5. Start the stable emulator

From the repository root:

```powershell
python .\server\assaultfire_server_v94.py
```

A healthy startup should identify the v94 build and start the local listeners used by the emulator.

The current stable branch uses the local VERSION, AUTH, DIR, ROLE, and ZONE services.

Do not expose these development listeners directly to the public internet. The project is intended for local/isolated preservation testing.

## 6. Start your Assault Fire PH client

Use the same client/configuration you use for your local emulator environment.

The project does not ship modified game binaries or client assets. Client-side setup therefore depends on the copy you already have.

For the **v94 public baseline**, use an existing known local profile/account path. Do not expect the unfinished first-time account/nickname creation flow to work.

## 7. What should I test first?

For a first test, keep it simple:

| Test | Expected state |
|---|---|
| Emulator starts without Python errors | Should work |
| VERSION connection | Should work |
| AUTH handshake | Should work |
| DIR/server discovery | Should work |
| Existing local profile reaches the established zone/login path | Stable baseline target |
| Basic profile/inventory state appears | Stable baseline target |
| First-ever account/nickname creation | Not supported in public v94 |
| Full PvE/The Altar round lifecycle | Not supported yet |
| Full real multiplayer/DS lifecycle | Not supported yet |

See [STATUS.md](STATUS.md) for the detailed matrix.

## 8. Something failed — what should I send?

Please do **not** send a 50 MB unsanitized dump first.

A useful bug report contains:

```text
Client version:
Server commit:
What I clicked/did:
What I expected:
What happened instead:

Relevant server log:
...

Packet command/opcode if known:
...

Does it reproduce after restarting both client and server?
Yes / No
```

Before uploading logs, remove:

- passwords
- private keys
- access tokens
- personal account information
- unrelated local filesystem details

Localhost addresses and project packet data are normally useful, but still review everything before posting publicly.

## 9. Beginner-friendly ways to contribute

You do not have to reverse engineer assembly.

Useful contributions include:

- improving documentation;
- turning known packet structures into Python dataclasses/parsers;
- adding tests around existing packet builders;
- cleaning duplicated server code without changing behavior;
- creating sanitized protocol examples;
- reproducing an open issue and reporting exactly what happened;
- documenting which stock-client button produces which command ID;
- comparing two sanitized packet captures;
- improving setup scripts and error messages.

If you **do** reverse engineer the client, describe behavior and structures in your own words. Do not commit the original executables, assets, or large copied blocks of proprietary decompiled/disassembled code.

## 10. Working on an unfinished feature

Start by checking [STATUS.md](STATUS.md).

For incomplete protocol work, a good contribution usually follows this pattern:

```text
1. Reproduce one client action.
2. Record the request command and sanitized body.
3. Identify the expected response family.
4. Verify field widths/order from evidence.
5. Implement the smallest response.
6. Test it with the stock client.
7. Document what was proven and what is still inferred.
```

Please avoid making large guessed packet structures just to make the UI stop complaining. Unknown nested structures should stay explicitly marked as unknown until evidence supports them.

## 11. Keep your branch safe

Create a feature branch:

```powershell
git checkout -b research/my-feature
```

Check what you are about to commit:

```powershell
git status
git diff
```

A good habit before every push:

```powershell
git status --short
```

If you see `PRIVATE.PEM`, game executables, DLLs, UPK/UDK files, dumps, databases, or personal logs, **do not commit them**.

## 12. Submit your work

Commit your changes:

```powershell
git add <only-the-files-you-intend-to-share>
git commit -m "docs: document A123 packet behavior"
git push -u origin research/my-feature
```

Then open a pull request and explain:

- what you changed;
- what evidence supports it;
- how you tested it;
- what is still uncertain.

Small, well-proven contributions are more useful than a huge patch built on guesses.

## Need help?

Open a GitHub issue describing the exact point where you are stuck. Include the smallest useful sanitized log or packet sample you have.

If you are unsure whether something is safe to publish, ask before uploading it.
