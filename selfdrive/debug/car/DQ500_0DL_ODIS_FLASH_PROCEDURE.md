# ODIS-E flash procedure — VW MQB DSG (DQ500 0DL) — WRITE side

**For READ, see the actual script `vw_mqb_dsg_uds_dump.py`. This doc is the
WRITE counterpart: the full sequence ODIS-E uses to flash an FRF on this
ECU family, derived from a real trace.**

Source trace: `/data/trace_logs/TMBLJ9NS3J8068062_20260519T154011_CAN.vmt`
(75920 lines). The trace was captured during a real ODIS-E flash of the
VW MQB EPS module (0x712, "0044 — Power steering"), VIN
TMBLJ9NS3J8068062 (Škoda Kodiaq). The session-entry + auth + transfer
pattern is **identical** across VW MQB ECUs — the only retarget for
the TCU is the tester ID (`0x7E1` instead of `0x712`), responder ID
(`0x7E9` instead of `0x77C`), and the SA2 byte-code (`6806814A05876B5F7DD5494C`
per `dq500_0dl.py:36`).

The functional broadcast address ODIS uses is **`0x700`** (VW tester
functional), not the ISO-14229 standard `0x7DF`. The trace shows the
suppress-positive-response bit set on every functional sub-function
(e.g. `0x80 | 0x03 = 0x83` for extended session broadcast).

---

## Phase 0 — Continuous keepalive

Throughout the entire session ODIS sends a TesterPresent broadcast
every ~500 ms:

```
0x700: 02 3E 80 ...
```

`0x3E` = TesterPresent, sub-function `0x80` = zeroSubFunction with
suppress-positive-response bit set. No ECU replies; all ECUs reset
their S3 timer (~5 s). Trace lines 3, 8, 13, 18 … repeated throughout.

---

## Phase 1 — Bus discovery

```
0x700: 02 01 00 ...                  ← OBD-II Mode01 PID00 functional
0x7E8: 06 41 00 98 3B A0 13          ← ECU supported PIDs (trace L25)
0x7E9: 06 41 00 98 18 00 01          ← TCU supported PIDs (trace L24)
```

ODIS does a quick OBD-II Mode 01 PID 00 broadcast to discover live
ECUs. Both engine (0x7E8) and TCU (0x7E9) respond with their PID
support bitmasks.

---

## Phase 2 — Target ECU session entry (per-ECU)

```
0x712: 02 10 02                      ← Programming session (trace L73)
0x77C: 03 7F 10 7E                   ← NRC 0x7E subFunctionNotSupportedInActiveSession
0x712: 03 22 F1 86                   ← Read DID F186 (current session)
0x77C: 04 62 F1 86 01                ← Response: in session 0x01 (default)
```

ODIS first speculatively tries `$10 02`. It NRCs — the ECU isn't ready
yet. ODIS reads `F186` (active session DID) to confirm state.

```
0x712: 02 10 03                      ← Extended session (trace L107)
0x77C: 06 50 03 00 32 01 F4          ← OK, P2=50ms, P2*=5000ms
0x712: 04 31 01 02 03                ← StartRoutine 0x0203 "Check Programming Precondition" (L109)
0x77C: 04 71 01 02 03                ← OK (no extra status byte for EPS)
0x712: 03 22 F1 5B                   ← Read DID F15B (ECU-specific identification)
0x77C: 10 35 62 F1 5B 00 01 01 …     ← multi-frame response
```

---

## Phase 3 — Bus-wide session promotion

```
0x700: 02 10 83                      ← Functional extended (L125)
                                       sub-function 0x83 = 0x80|0x03
                                       (suppress + extendedDiagnosticSession)
```

ALL ECUs go into extended session simultaneously. No echo because
suppress-positive bit set.

```
0x712: 02 10 03                      ← Per-ECU extended re-confirm (L126)
0x77C: 06 50 03 00 32 01 F4          ← OK
0x712: 04 31 01 02 03                ← Routine 0x0203 again (L129)
0x77C: 04 71 01 02 03                ← OK
```

---

## Phase 4 — Bus quiescence

```
0x700: 05 85 82 FF FF FF             ← Functional ControlDTCSetting OFF (L131)
                                       0x82 = 0x80|0x02 (suppress + DTC OFF)
                                       0xFFFFFF = all DTC groups
0x77D: 03 7F 85 78                   ← NRC 0x78 responsePending (gateway 0x77D)
0x77D: 02 C5 02                      ← Positive (after delay)

0x700: 03 28 81 01                   ← Functional CommunicationControl (L135)
                                       0x81 = 0x80|0x01 (suppress + disableRxNormalCommunication)
                                       0x01 = normalCommunication
```

**After these two broadcasts: no ECU will log DTCs, and no ECU will
broadcast normal-priority frames.** This is the critical state that
unlocks `$10 02` on the target.

---

## Phase 5 — Programming session (target ECU)

```
0x712: 02 10 02                      ← Programming session (L137)
0x77C: 03 7F 10 78                   ← NRC 0x78 responsePending
0x77C: 06 50 02 00 0A 01 F4          ← OK!  (L139)  P2=10ms, P2*=5000ms
```

**ECU is now in CBOOT.** Its ASW is suspended; normal broadcasts stop;
only programming-relevant services are available.

---

## Phase 6 — SecurityAccess L17

```
0x712: 02 27 11                      ← Request seed (L140)
0x77C: 06 67 11 D7 DD 14 E8          ← Seed = 0xD7DD14E8
0x712: 06 27 12 16 56 DD A8          ← Send key = 0x1656DDA8 (computed locally
                                       from seed via SA2 byte-code VM)
0x77C: 03 7F 27 78                   ← responsePending
0x77C: 02 67 12                      ← OK — SA17 unlocked
```

Key derivation: feed the 4-byte big-endian seed integer into the SA2
byte-code VM with the per-ECU `sa2_script`. For DQ500 0DL the script
is `6806814A05876B5F7DD5494C` (per `VW_Flash/lib/modules/dq500_0dl.py:36`).
Same algorithm VW_Flash uses on this ECU family. Wrong key bumps the
lockout counter (NRC `0x35 invalidKey`); after a few attempts NRC
`0x36 exceededNumberOfAttempts` time-locks SA until a delay expires.

---

## Phase 7 — Workshop code write (REQUIRED prerequisite for $34)

```
0x712: 10 0C 2E F1 5A 26 05 19       ← FirstFrame, length 12, $2E DID 0xF15A,
                                       payload starts 26 05 19 …
0x77C: 30 0F 00                      ← FlowControl, blockSize 0x0F, STmin 0
0x712: 21 11 11 11 11 11 11          ← ConsecutiveFrame: 11 11 11 11 11 11
0x77C: 03 6E F1 5A                   ← Positive response to $2E F1 5A
```

The 9-byte workshop code written to DID `0xF15A`:

```
26          = year   (BCD/hex since 2000 → 2026)
05          = month  (May)
19          = day    (the 19th)
11 11 11 11 11 11 = workshop ID (this trace used all-0x11; VW_Flash
                                  defaults to 0x42 04 20 42 B1 3D)
```

The ECU records the workshop tag for traceability in flash logs. The
ASW state machine on many VW MQB ECUs (DQ500 included) **refuses
`$34 RequestDownload` until `0xF15A` has been written this session.**

---

## Phase 8 — Per-block flash write loop

For each block in the FRF (DQ500 0DL: CBOOT=1, ASW=2, CAL=3):

### 8a. Erase

```
0x712: 04 31 01 FF 00 01 <BB>        ← StartRoutine 0xFF00 EraseMemory
                                       arg = (0x01, block_id)
                                       trace L685 = block 0x50
                                       (NOTE: EPS uses different block
                                       IDs than DQ500 0DL; DQ500 uses
                                       1/2/3 per dq500_0dl.py)
0x77C: 04 71 01 FF 00                ← OK (after responsePending)
```

DQ500 specifically: `dq500_0dl.py:78` sets `erase_retries=5` because
the CBOOT erase splits internally and NRCs between phases. The flasher
retries the routine until it positively succeeds.

### 8b. RequestDownload

```
0x712: 10 08 34 00 41 <BB> <SS SS SS SS>
                                     ← FF, length 8, $34 with:
                                       data_format = 0x00 (no comp/enc)
                                       addressFormat = 0x41 (4-byte len,
                                                             1-byte addr)
                                       address = block_id (1 byte)
                                       size = 4 bytes
                                       trace L149: block 0x30, size 0x0D18
0x77C: 04 74 20 02 02                ← Positive: maxNumberOfBlockLength = 0x0202
                                       (514 bytes max per $36)
```

DQ500 0DL uses `block_transfer_sizes = 0x800` (2048 B) per `$36` per
`dq500_0dl.py:11`. Different ECUs negotiate different chunk sizes.

### 8c. TransferData loop

```
0x712: 1N NN 36 <ctr> <payload bytes …>    ← FirstFrame
0x77C: 30 0F 00                            ← FlowControl
0x712: 2N <payload continuation …>         ← ConsecutiveFrame(s)
...
0x77C: 03 76 <ctr>                         ← Positive response when chunk done
```

Counter starts at 1, wraps `0xFF → 0x00`. Each $36 carries one chunk
of encrypted+compressed flash data from the FRF.

### 8d. RequestTransferExit

```
0x712: 01 37                         ← $37
0x77C: 01 77                         ← OK
```

### 8e. ChecksumBlock

```
0x712: 10 0C 31 01 02 02 01 30       ← FF, $31 01 02 02 = StartRoutine 0x0202
                                       data = (0x01, block_id, 0x00, 0x04,
                                               <4-byte expected CRC>)
                                       trace L680
0x77C: 04 71 01 02 02                ← Positive — block CRC matches
```

NRC here = bricked block. Flasher aborts.

---

## Phase 9 — Verify dependencies + reset

```
0x712: 04 31 01 FF 01                ← StartRoutine 0xFF01 (trace L75033)
                                       CheckProgrammingDependencies
0x77C: 04 71 01 FF 01                ← OK
0x712: 02 11 01                      ← $11 01 ECUReset(hardReset) (L75035)
0x77C: 03 7F 11 78                   ← responsePending
                                       (ECU reboots; no further response)
```

---

## Phase 10 — Cleanup

```
0x700: 05 85 82 FF FF FF             ← DTC off again (L75039) — paranoia
0x700: 03 28 81 01                   ← Tx silenced again (L75041) — paranoia
0x700: 03 28 80 01                   ← Tx RE-ENABLED (L75042)
                                       0x80 = (0x80 suppress | 0x00 enableRxAndTx)
0x700: 05 85 81 FF FF FF             ← DTC RE-ENABLED (L75044)
                                       0x81 = (0x80 suppress | 0x01 on)

0x712: 02 10 01                      ← Default session, twice (L75049, 75064)
```

The ECU comes back up after its hardReset, all other ECUs return to
normal traffic.

---

## Mapping to `dq500_0dl.py` constants

| ODIS field             | Trace value     | `dq500_0dl.py`                            |
|------------------------|-----------------|-------------------------------------------|
| Tester ID              | `0x712` (EPS)   | `0x7E1` (TCU)                             |
| Responder ID           | `0x77C`         | `0x7E9`                                   |
| SA level               | 17 (`0x11`)     | `flash_uds.py:519` says SA17              |
| SA2 byte-code          | EPS-specific    | `6806814A05876B5F7DD5494C`                |
| Block IDs              | EPS 0x30, 0x50  | 1=CBOOT, 2=ASW, 3=CAL (`block_identifiers_dsg`) |
| Block sizes            | EPS varies      | CBOOT 0x1FE00, ASW 0x10FE00, CAL 0x3FE00  |
| $36 chunk size         | 514 B (EPS)     | 0x800 = 2048 B (`block_transfer_sizes_dsg`) |
| Erase retries          | n/a             | 5 (`flash_info.erase_retries = 5`)         |

---

## Where the READ path diverges

Phases 0-6 are reusable verbatim (only retargeted to TCU IDs). After
SA17 unlock, the READ path substitutes `$35 RequestUpload` for the
ODIS `$2E F1 5A` + `$31 0xFF00` + `$34 RequestDownload` chain, then
runs the same `$36` / `$37` pair (where `$36` data flows tester-ward
in upload mode). **No erase, no checksum, no ECU reset, no workshop
code write.** See `vw_mqb_dsg_uds_dump.py` for the operational script.
