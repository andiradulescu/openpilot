# DQ500 0DL TCU (Bosch, Renesas R5F72549R / SH-2A) — Flash Map

User-supplied + screenshot-verified, 2026-05-17. Used by
`vw_mqb_dsg_uds_dump.py` to pick which addresses to probe.

## Main program flash (`R5F72549R`, total `0x280000` = 2,560 KB)

| Range                       | Partitions     | Per-part size | Access     | FRF block        |
|-----------------------------|----------------|---------------|------------|------------------|
| `0x00000000 – 0x0000FFFF`   | 1–8            | 8 KB          | protected  | SBOOT            |
| `0x00010000 – 0x0009FFFF`   | 9–17           | 64 KB         | protected  | CBOOT, ASW (low) |
| `0x000A0000 – 0x0013FFFF`   | 18–22          | 128 KB        | protected  | ASW (high)       |
| `0x00140000 – 0x0017FFFF`   | 23–24          | 128 KB        | **readable** (calibration) | CAL |
| `0x00180000 – 0x0027FFFF`   | 25–32          | 128 KB        | protected  | factory          |

## Data flash / EEPROM (total `0x20000` = 128 KB)

| Range                       | Partitions     | Per-part size | Access     |
|-----------------------------|----------------|---------------|------------|
| `0x80100000 – 0x8011FFFF`   | 1–16           | 8 KB          | **readable** |

Holds adaptation, immobilizer, mileage, learned values.

## Expected behavior

- **CAL (`0x00140000–0x0017FFFF`)** and **EEPROM (`0x80100000–0x8011FFFF`)**:
  readable after SecurityAccess L17 via `$35 RequestUpload` (4-byte
  physical-address form) + `$36/$37`. Confirmed by YOYO Diagnostic
  screenshots; the tool's "Read MAPS" / "Backup EEPROM" succeeds on
  exactly these ranges.
- **All other partitions**: protected. YOYO refuses to even ask
  ("Skip the protection partition N/32") — the bootloader has these
  read-disabled at the flash-protection-bit level.

## YOYO Diagnostic screenshots — empirical reference

Source: `/data/VW_Flash/screenshots/IMG_1610..IMG_1619.PNG`. The tool
labels this ECU family `BOSCH_DQ381_SM72xxx`; DQ381 SM72xx and DQ500 0DL
share the same Renesas R5F72549R and flash topology.

`IMG_1610` — ECU identity:
- MCU: `R3F72549R` (= R5F72549R / SH-2A)
- Boot: `bh1g0301`, Bosch P/N: `1034620266`
- **Flash Size: `0x00280000`** = 2,560 KB ✓
- **EEPROM Size: `0x00020000`** = 128 KB ✓

`IMG_1613` / `IMG_1615` / `IMG_1616` — "Read MAPS" log:
- Iterates all 32 main-flash partitions. For each, log is either:
  - `"Skip the protection partition N/32, Address: 0xNNNNNNNN, size XXX Bytes"`
    → not readable (SBOOT, CBOOT, ASW, upper factory).
  - `"Reading partition N/32 Address: 0xNNNNNNNN size XXX Bytes"`
    → readable. Matches partitions 23-24 (CAL).
- Then "Reading EEPROM..." → 16 partitions at base `0x80100000`,
  all readable.

`IMG_1617` — `.bin` / `.ecu` outputs from the tool.

`IMG_1618` / `IMG_1619` — hex view of the produced dump (ASCII tags
visible — calibration block layout).

## YOYO read protocol (inferred)

YOYO uses the **same UDS services as VW_Flash**'s flasher, but with a
different addressing form on the upload side:

- `$10 03` ExtendedDiagnostic (same as flasher)
- `$27` SecurityAccess L17 with the DSG SA2 byte-code
  (`6806814A05876B5F7DD5494C` from `dq500_0dl.py:36` — same as flasher)
- `$35` RequestUpload with **`addressAndLengthFormatIdentifier = 0x44`**
  (4-byte length, 4-byte address) + `data_format = 0x00` (no
  compression/encryption) — *different from the flasher, which writes
  with `address_format=8` block-ID*
- `$36` TransferData loop until done
- `$37` RequestTransferExit

Each readable partition is read in its own `$35/$36/$37` cycle, sized
per the partition geometry above.

## Address-form heuristic

VW Bosch ECUs accept multiple address conventions for `$23` and `$35`:
1. Physical-flash offset (`0x00140000` for CAL) — what YOYO uses.
2. SH-2A bus VA (`0x80140000` for CAL — `0x80000000` + offset).
3. EEPROM uses the bus-VA form (`0x80100000+offset`) — confirmed by
   screenshots; YOYO issues reads at exactly that base.
4. Block-ID form (`addr=1/2/3` for CBOOT/ASW/CAL) — what VW_Flash uses
   on the WRITE side, not seen on the YOYO read side.

Empirical result (Phase A, this session): `$23 ReadMemoryByAddress`
returns NRC `0x11 serviceNotSupported` on every region in extended
session without SA. The YOYO path goes through `$35`, not `$23`, after
SA17 — so `$35` after SA is the path we need to mirror.
