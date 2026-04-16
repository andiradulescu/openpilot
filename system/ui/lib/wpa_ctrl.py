"""wpa_supplicant parsing helpers."""

_HEX = "0123456789abcdefABCDEF"


def decode_ssid(encoded: str) -> str:
  """Decode a wpa_supplicant printf_encode'd SSID (hostap common.c:526).
  Escapes: \\\\, \\", \\e/n/r/t, \\xNN/\\xN, octal \\0..\\777.
  Bytes are reinterpreted as UTF-8; all-null SSIDs (hidden APs) normalize to ""."""
  out = bytearray()
  i = 0
  n = len(encoded)
  while i < n:
    c = encoded[i]
    if c != "\\":
      out.append(ord(c) & 0xff)
      i += 1
      continue

    i += 1  # consume backslash
    if i >= n:
      break  # trailing backslash: dropped

    nxt = encoded[i]
    if nxt == "\\":
      out.append(ord("\\"))
      i += 1
    elif nxt == '"':
      out.append(ord('"'))
      i += 1
    elif nxt == "n":
      out.append(ord("\n"))
      i += 1
    elif nxt == "r":
      out.append(ord("\r"))
      i += 1
    elif nxt == "t":
      out.append(ord("\t"))
      i += 1
    elif nxt == "e":
      out.append(0x1b)
      i += 1
    elif nxt == "x":
      i += 1  # consume 'x'
      if i + 1 < n and encoded[i] in _HEX and encoded[i + 1] in _HEX:
        out.append(int(encoded[i:i + 2], 16))
        i += 2
      elif i < n and encoded[i] in _HEX:
        out.append(int(encoded[i], 16))
        i += 1
      # else: malformed \x — drop the escape, continue parsing at i
    elif "0" <= nxt <= "7":
      val = ord(nxt) - ord("0")
      i += 1
      if i < n and "0" <= encoded[i] <= "7":
        val = val * 8 + (ord(encoded[i]) - ord("0"))
        i += 1
        if i < n and "0" <= encoded[i] <= "7":
          val = val * 8 + (ord(encoded[i]) - ord("0"))
          i += 1
      out.append(val & 0xff)
    # else: unknown escape — the backslash is consumed, the char falls
    # through to the next iteration and is appended as a literal.

  if not out or all(b == 0 for b in out):
    return ""
  return out.decode("utf-8", errors="replace")


def parse_status(raw: str) -> dict[str, str]:
  """Parse wpa_supplicant STATUS output (key=value lines). `ssid` is decoded."""
  result = {}
  for line in raw.strip().split("\n"):
    if "=" in line:
      key, _, value = line.partition("=")
      if key == "ssid":
        value = decode_ssid(value)
      result[key] = value
  return result


def dbm_to_percent(dbm: int) -> int:
  """Convert dBm to percentage [0, 100], matching NetworkManager's scale."""
  v = abs(max(-100, min(-40, dbm)) + 40)
  return 100 - (100 * v) // 60
