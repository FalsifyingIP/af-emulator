# Launcher / AP / TGame Error Reference

This is the FYI troubleshooting reference for Assault Fire PH launcher and early game-start errors.

It documents errors and warning codes that the project has actually observed or recovered. Unknown codes stay marked **unknown** instead of receiving a guessed meaning.

## Quick rule

Identify the stage first:

~~~text
client.exe / TCLS
  -> VERSION
  -> AP / AUTH
  -> DIR
  -> ROLE / TACC
  -> TCLS -> TGame handoff
  -> TGame startup
  -> TGame ROLE / ZONE
~~~

A popup after TGame appears is not automatically an AP/AUTH error.

---

## 1. AP / AUTH errors

The stable AUTH service uses the legacy AP protocol on TCP port 8000.

Verified success flow:

~~~text
client AP request
 -> RSA / DH
 -> AES session
 -> AP cmd 3
 -> server AP cmd 4 result
 -> client AP cmd 5 acknowledgement
~~~

### AP cmd 4 result fields

Recovered layout:

~~~text
u32 error_code
u32 oas_error_code
u32 error_message_length
char error_message[...]
u32 uid
u32 timestamp
u16 ticket_size
byte ticket[...]
~~~

Stable local success uses:

~~~text
error_code     = 0
oas_error_code = 0
~~~

A complete numeric mapping for every historical AP/OAS code has **not** been recovered. For any unknown non-zero code, record both codes, the returned error message, AP command, sequence, and server log.

### FAILED to load RSA private key

Server-side symptom:

~~~text
[BOOT] FAILED to load RSA private key: ...
~~~

Check:

- server/PRIVATE.PEM exists;
- AF_PRIVATE_KEY is correct;
- PEM is valid and unencrypted.

Regenerate the matching pair with:

~~~powershell
.\.venv\Scripts\python.exe .\tools\setup\generate_local_rsa_keypair.py --client-config-dir "D:\YourAssaultFireFolder\TCLS\config"
~~~

### RSA decrypt / verify failure

First check that these are from the same generated pair:

~~~text
server/PRIVATE.PEM
TCLS/config/APClient.dat
~~~

A mismatched pair will break AP authentication.

### wrong AP sync word

Expected encrypted AP frames begin with:

~~~text
HNNW
~~~

This error means the connection is not in the AP frame state expected by the server or the framing is corrupt.

### short AP header / short AP body

The peer closed or framing ended before the advertised AP packet was complete.

### invalid AP padding marker / invalid AP logical length

Investigate:

- wrong AES key;
- incorrect DH-derived session;
- wrong ciphertext boundary;
- client/server AP state mismatch.

### No cmd=5 received

Important checkpoint:

~~~text
server -> AP cmd 4
client -> AP cmd 5
~~~

If cmd 5 never arrives, do not treat AUTH as fully accepted just because the server transmitted cmd 4.

---

## 2. TCLS launcher errors

### Get Game Server Info fail!

Observed TCLS log:

~~~text
[Launch][CLaunchUI::GetLoginInfo]Get Game Server Info fail!
~~~

Verified check on the known TCLS build:

~~~text
TCLS.dll + 0x5C236
~~~

Meaning: the selected game-server-information result tested by CLaunchUI::GetLoginInfo was empty/zero at that point.

Check:

- DIR tree acceptance;
- selected server/leaf;
- server ID / leaf relationship;
- endpoint URI;
- selected-server object population.

Important: execution continues after this log, so the line alone does not prove immediate launch abort.

### Get loginInfo fail!

Observed historically when TCLS could not obtain the launch/login handoff information TGame needed.

Treat this as a **TCLS -> TGame handoff problem**, not automatically an AP password/authentication error.

Check:

- AP login completion;
- UIN/profile state;
- selected server information;
- shared-memory handoff;
- normal TCLS-created TGame path.

---

## 3. TGame network popup

### Network is disconnected:Connection Closed!

Observed popup:

~~~text
Network is disconnected:Connection Closed!
~~~

This was reproduced after TGame successfully started and connected to the local role/game endpoint, but the server closed the socket without completing the expected handshake.

So this popup can mean TGame progressed farther than the launcher.

Check:

- ROLE port 65005;
- whether OWNER=TGame.exe is seen;
- transport handshake;
- early socket close;
- TCLS-delivered session data.

Do not automatically rewrite VERSION/AUTH if those earlier stages are already proven.

---

## 4. Legacy security / TenProtect warnings

These are client security-driver compatibility warnings, **not AP error codes**.

### Warning (1, 81008, 4B)

Observed on a clean/fresh legacy security-driver initialization path.

Historical text was approximately:

~~~text
Try the game drive abnormal, please restart the game
~~~

Classification: **confirmed driver/security-component unhealthy path**.

A captured run displayed the warning and then deliberately exited with process code 0.

### Warning (1, 1008, 4B)

Observed during historical compatibility research.

Associated text indicated a multiple-instance / conflicting-client condition.

Classification: **observed; likely multiple-instance/conflicting-environment warning**.

### Warning (1, 2008, 4B)

Classification: **observed; exact meaning unknown**.

Do not assign a guessed meaning.

### Warning (1, 100000, 4B)

Associated text indicated the Tencent security system detected an anomalous program/environment.

Classification: **observed security/environment warning**.

Not an AP server error.

### Warning (3, 80000, 4B)

Observed in a stale/already-loaded legacy security-driver state.

One captured run later ended in:

~~~text
0xC0000005
~~~

Classification: **observed stale/environment security-driver path**.

Do not confuse it with the clean (1, 81008, 4B) path.

### Warning (4, 8000, 54)

Associated observed text:

~~~text
The game file is corrupted ... try again! (2141D)
~~~

Classification: **observed late integrity/security warning**.

Historical testing showed this warning could remain after temporary research instrumentation had already been removed, so it does not automatically prove the emulator modified a game file.

---

## 5. Legacy security-loader prompt

### 自加载初始化失败

Approximate English meaning:

~~~text
self-loading initialization failed
~~~

Classification: **legacy security-loader / modern-Windows compatibility problem**.

It is not an AP/DIR error.

See Issue #4.

---

## 6. Windows exit / crash codes

### 0xC000071C — STATUS_INVALID_THREAD

Observed very early in TGame startup on modern Windows.

Historical traces tied it to obsolete legacy protection/thread-management behavior interacting badly with modern Windows threadpool handling.

Classification: **client/OS compatibility failure**.

Do not diagnose this as AUTH/DIR.

### 0xC0000005 — access violation

Generic invalid-memory-access exception.

It is a crash code, not a root cause.

Collect:

- crash module/address;
- preceding warning;
- whether TGame reached ROLE/ZONE;
- fresh vs stale legacy-driver state.

### 0x00000000 after a warning

A zero exit code does not always mean success.

The legacy protection layer was observed showing a warning and deliberately terminating TGame with exit code 0.

---

## 7. TGame datetime error

The validated PH TGame build can receive a bad/pre-1900 datetime value and crash in a legacy conversion path.

Run:

~~~powershell
.\.venv\Scripts\python.exe .\tools\patches\patch_tgame_datetime.py
~~~

Validated site:

~~~text
TGame.exe + 0x010B9510
~~~

Expected original bytes:

~~~text
83 EC 24 53 8B 5C 24 2C
~~~

### TGame build/signature mismatch

The patcher can report:

~~~text
TGame build/signature mismatch.
Nothing was patched.
~~~

This is a safety check.

It means the running TGame does not match the validated function signature. Do not force the same address onto an unknown build.

---

## 8. Fast diagnosis table

| Symptom | First area to check |
|---|---|
| No VERSION request | hosts/DNS, port 9060, server running |
| VERSION works, AP fails | port 8000, RSA pair, AP framing |
| AP cmd 4 sent, no cmd 5 | client did not finish/accept AUTH |
| AUTH succeeds, no server list | DIR tree / attributes / 9010 |
| Server list exists, START does nothing | selected server / TCLS GetLoginInfo |
| Get Game Server Info fail! | DIR selected-game-server data |
| TGame never appears | TCLS launch/shared-memory handoff |
| TGame appears then dies | datetime / legacy compatibility |
| STATUS_INVALID_THREAD | legacy security layer vs modern Windows |
| security warning tuple appears | client security-driver path, not AP |
| Connection Closed! | TGame ROLE/transport connection |
| ROLE works, no ZONE | game-side session/handoff |
| ZONE works, gameplay state broken | gameplay protocol/state |

---

## 9. Reporting an unknown launcher/AP error

Capture:

~~~text
Exact popup/log text:
Numeric code(s):
Window title:
client.exe/TCLS or TGame.exe:
Last server stage reached:
  VERSION / AUTH / DIR / ROLE / ZONE

AP information if relevant:
  command:
  error_code:
  oas_error_code:
  error_message:
  sequence:

TGame exit code:
Windows version:
TGame/TCLS hashes if known:
~~~

Then open an issue.

Do not guess a meaning simply because a code looks similar to another one.

---

## 10. Coverage note

The original PH installation contains a prompt.ini message catalog, but the complete retail numeric-to-text mapping has not yet been independently recovered into this repository.

So this page currently documents:

**all launcher/AP/TGame errors the project has verified or actually observed so far**

—not every possible retail-era error that ever existed.

When more are recovered, add:

- exact code;
- exact text where available;
- component/stage;
- reproducible evidence;
- confirmed / likely / unknown classification.
