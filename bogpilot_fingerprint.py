#!/usr/bin/env python3
"""
bogpilot_fingerprint.py - make a small, privacy-safe "car fingerprint" file from your own
openpilot / BogPilot / FrogPilot rlogs, for adding or improving support for legacy Teslas
(Model S/X AP1 and similar pre-AP2 cars) in BogPilot.

Runs entirely on your own computer. It never connects to the internet and never uploads anything.

    python3 bogpilot_fingerprint.py <route folder | rlog files...> -o my_car_fingerprint.json

What goes in the output (and nothing else):
  * CAN fingerprint: per bus, which message addresses appear, their length and rate (no payload bytes)
  * firmware versions the car reported (carParams.carFw), with VIN / long numbers redacted
  * carParams fields useful for porting (no VIN)
  * software version / branch (personal fork names hidden), device model
  * panda hardware type and safety mode
  * optional (--include-can-stats): per-address "which bits change" + per-byte min/max, never for
    addresses that can carry VIN, odometer, location or clock data
  * optional coverage report (Tesla DBC bundled): which recording-checklist signals were seen

Dependencies: pycapnp, zstandard (plus the Python standard library). MIT licensed.
"""
import argparse
import bz2
import collections
import io
import json
import math
import os
import re
import statistics
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL_VERSION = "1.0.0"

# ----------------------------------------------------------------------------------------------
# Privacy rules
# ----------------------------------------------------------------------------------------------

# Addresses whose payload statistics are never exported (fingerprint presence/length/rate is
# still listed, because the address alone carries no personal data). Sources: BogPilot opendbc
# tesla_can.dbc / tesla_radar_bosch_generated.dbc, OVMS Tesla Model S decoder, wk057 CAN notes.
STATS_DENYLIST = {
  0x508: "VIN (Model S CAN3: 3 pages of ASCII VIN characters)",
  0x2B9: "VIN sent to the Bosch radar (VIN_VIP_405HS, radar bus)",
  0x5D8: "odometer",
  0x562: "battery odometer",
  0x209: "odometer sent to the radar (GTW_odo, radar bus)",
  0x3D2: "lifetime energy counters",
  0x3D8: "GPS latitude/longitude (MCU_locationStatus)",
  0x068: "GPS elevation (MCU_locationStatus2)",
  0x2F8: "GPS heading/speed (UI_gpsVehicleSpeed)",
  0x246: "sun position (reveals time and place, UI_solarData)",
  0x3C8: "map data / country code (UI_driverAssistMapData)",
  0x398: "country code (GTW_carConfig)",
  0x318: "wall-clock date and time (GTW_carState)",
}
# UDS / diagnostic range: responses can carry VIN, part serials, etc.
DIAG_RANGE = (0x600, 0x7FF)

# Known public openpilot forks: for these, branch and commit are kept. Anything else (e.g. a
# personal fork named after a GitHub user) keeps only the repository name.
PUBLIC_OWNERS = {"commaai", "bogpilot", "frogai", "sunnypilot", "sunnyhaibin", "dragonpilot-community",
                 "openpilotusa", "twilsonco", "pfeiferj"}

VIN_CHARS = "ABCDEFGHJKLMNPRSTUVWXYZ0123456789"
VIN_TOKEN = re.compile(r"(?<![A-Za-z0-9])[A-HJ-NPR-Z0-9]{17}(?![A-Za-z0-9])")
LONG_NUMBER = re.compile(r"\d{10,}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
MAC_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")
COORD_RE = re.compile(r"(-?\d{1,3}\.\d{5,})[^0-9-]{1,30}?(-?\d{1,3}\.\d{5,})")
WORDS_RE = re.compile(r"(?i)dongle|serial|imei|iccid|/home/|/users/|/data/media|androidboot")


def looks_like_vin(tok):
  letters = sum(c.isalpha() for c in tok)
  digits = sum(c.isdigit() for c in tok)
  return letters >= 2 and digits >= 3


def redact_text(s, secrets):
  """Redact VIN-like tokens, known secrets and long digit runs inside a firmware string."""
  notes = []
  for sec in secrets:
    if sec and len(sec) >= 5 and sec.lower() in s.lower():
      s = re.sub(re.escape(sec), "<redacted>", s, flags=re.I); notes.append("known identifier")
  for m in list(VIN_TOKEN.finditer(s)):
    if looks_like_vin(m.group(0)):
      s = s.replace(m.group(0), "<redacted-vin>"); notes.append("VIN-like text")
  if LONG_NUMBER.search(s):
    s = LONG_NUMBER.sub("<redacted-number>", s); notes.append("long number")
  return s, notes


def bytes_repr(b):
  """openpilot-style b'...' literal (printable ASCII kept, rest as \\xNN)."""
  out = []
  for c in b:
    ch = chr(c)
    if ch == "\\":
      out.append("\\\\")
    elif ch == "'":
      out.append("\\'")
    elif 32 <= c < 127:
      out.append(ch)
    else:
      out.append(f"\\x{c:02x}")
  return "b'" + "".join(out) + "'"


# ----------------------------------------------------------------------------------------------
# Log reading (no openpilot checkout needed: bundled cereal schema + pycapnp)
# ----------------------------------------------------------------------------------------------

def load_schema(schema_dir):
  try:
    import capnp
  except ImportError:
    sys.exit("pycapnp is missing. Install it with:  python3 -m pip install pycapnp zstandard")
  capnp.remove_import_hook()
  return capnp.load(os.path.join(schema_dir, "log.capnp"), imports=[str(schema_dir)])


def decompress(path):
  data = Path(path).read_bytes()
  if data[:4] == b"\x28\xb5\x2f\xfd":
    try:
      import zstandard
    except ImportError:
      sys.exit("zstandard is missing. Install it with:  python3 -m pip install zstandard")
    return zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)).read()
  if data[:3] == b"BZh":
    return bz2.decompress(data)
  return data


RLOG_NAME = re.compile(r"(^|--)rlog(\.bz2|\.zst)?$")


def seg_index(p):
  for part in (p.parent.name, p.name):
    m = re.search(r"--(\d+)(?:--rlog.*)?$", part)
    if m:
      return int(m.group(1))
  return 0


def find_rlogs(paths):
  files = []
  for p in map(lambda x: Path(x).expanduser(), paths):
    if p.is_file():
      files.append(p)
    elif p.is_dir():
      files += [f for f in p.rglob("*") if f.is_file() and RLOG_NAME.search(f.name)]
    else:
      sys.exit(f"Not found: {p}")
  qlogs = [f for f in files if "qlog" in f.name]
  if qlogs:
    print(f"Note: ignoring {len(qlogs)} qlog file(s); rlogs are needed.", file=sys.stderr)
  files = [f for f in files if "qlog" not in f.name]
  if not files:
    sys.exit("No rlog / rlog.zst / rlog.bz2 files found. Point this at the route folder that contains the "
             "<route>--0, <route>--1 ... folders, or at the rlog files themselves.")
  return sorted(set(files), key=lambda f: (seg_index(f), str(f)))


WANTED = {"can", "sendcan", "carParams", "initData", "pandaStates", "pandaStateDEPRECATED", "peripheralState"}


def iter_events(log, path):
  it = iter(log.Event.read_multiple_bytes(decompress(path), traversal_limit_in_words=2**62))
  while True:
    try:
      evt = next(it)
    except StopIteration:
      return
    except Exception:
      # truncated / corrupted segment (e.g. car switched off while writing): keep what we have
      print(f"  note: {os.path.basename(os.path.dirname(path)) or path} ends early (truncated); using the part that could be read",
            file=sys.stderr)
      return
    try:
      w = evt.which()
    except Exception:
      continue
    if w in WANTED:
      yield w, evt


# ----------------------------------------------------------------------------------------------
# Minimal DBC parser for the coverage report
# ----------------------------------------------------------------------------------------------

class Signal:
  def __init__(self, name, start, size, little, signed):
    self.name, self.size, self.signed = name, size, signed
    if little:
      bits = list(range(start, start + size))[::-1]          # MSB first
    else:
      bits, pos = [], start
      for _ in range(size):
        bits.append(pos)
        pos = pos + 15 if pos % 8 == 0 else pos - 1
    self.bits = bits
    self.mask = sum(1 << b for b in bits)

  def decode(self, x):
    v = 0
    for b in self.bits:
      v = (v << 1) | ((x >> b) & 1)
    if self.signed and v >> (self.size - 1):
      v -= 1 << self.size
    return v


def parse_dbc(path):
  msgs, vals, cur = {}, {}, None
  for line in Path(path).read_text(errors="replace").splitlines():
    m = re.match(r"^BO_ (\d+) (\w+):\s*(\d+)", line)
    if m:
      cur = int(m.group(1)) & 0x1FFFFFFF
      msgs[cur] = {"name": m.group(2), "len": int(m.group(3)), "signals": {}}
      continue
    m = re.match(r"^\s+SG_ (\w+)\s*(?:m\d+|M)?\s*:\s*(\d+)\|(\d+)@([01])([+-])", line)
    if m and cur is not None:
      msgs[cur]["signals"][m.group(1)] = Signal(m.group(1), int(m.group(2)), int(m.group(3)), m.group(4) == "1", m.group(5) == "-")
      continue
    m = re.match(r"^VAL_ (\d+) (\w+) (.*);", line)
    if m:
      vals[(int(m.group(1)), m.group(2))] = {int(a): b for a, b in re.findall(r"(-?\d+) \"([^\"]*)\"", m.group(3))}
  return msgs, vals


# DBC per bus for legacy Tesla (BogPilot CANBUS: 0 chassis, 1 radar, 2 autopilot chassis, 4 powertrain,
# 6 autopilot powertrain).
TESLA_BUS_DBC = {0: "tesla_can.dbc", 2: "tesla_can.dbc", 4: "tesla_powertrain.dbc", 6: "tesla_powertrain.dbc"}

# Recording-checklist signals, in three tiers. CORE/OPTIONAL list only signals BogPilot's legacy-Tesla code actually reads
# (selfdrive/car/tesla/carstate.py, values.py BUTTONS/DOORS, cluster.py, blindspot.py).
# CORE = needed for a basic port; OPTIONAL = extra BogPilot features; FUTURE = planned BogPilot features.
# kind: "enum"    small state values; lists the values seen, "need" = values that must appear
#       "cont"    continuous value; must change at least once
#       "zero"    continuous value; must reach 0 at least once (standstill)
#       "present" message must be present (no change expected)
def C(tier, step, msg, sig, kind, feature, need=(), when=None):
  return {"tier": tier, "step": step, "msg": msg, "sig": sig, "kind": kind, "feature": feature, "need": list(need), "when": when}

CHECKLIST = [
  C("CORE", "Vehicle speed", "ESP_B", "ESP_vehicleSpeed", "cont", "vEgo for all control"),
  C("CORE", "Standstill (speed reaches 0)", "ESP_B", "ESP_vehicleSpeed", "zero", "standstill / stop-and-go"),
  C("CORE", "Gear P/R/D (N optional)", "DI_torque2", "DI_gear", "enum", "engage only in D, reverse handling",
    need=("DI_GEAR_P", "DI_GEAR_R", "DI_GEAR_D")),
  C("CORE", "Accelerator pedal", "DI_torque1", "DI_pedalPos", "cont", "gas-pressed / override"),
  C("CORE", "Brake pedal", "BrakeMessage", "driverBrakeStatus", "enum", "disengage on brake", need=("APPLIED", "NOT_APPLIED")),
  C("CORE", "Steering angle (EPAS)", "EPAS_sysStatus", "EPAS_internalSAS", "cont", "lateral (angle) control"),
  C("CORE", "Steering rate", "STW_ANGLHP_STAT", "StW_AnglHP_Spd", "cont", "steering rate for lateral control"),
  C("CORE", "Driver steering torque", "EPAS_sysStatus", "EPAS_torsionBarTorque", "cont", "steeringTorque"),
  C("CORE", "Hands-on level", "EPAS_sysStatus", "EPAS_handsOnLevel", "enum", "steering override (steeringPressed)"),
  C("CORE", "EPAS status", "EPAS_sysStatus", "EPAS_eacStatus", "enum", "steer available / fault detection"),
  C("CORE", "EPAS error code", "EPAS_sysStatus", "EPAS_eacErrorCode", "present", "temporary steer-fault warnings"),
  C("CORE", "EPB EAC allow (0x214)", "EPB_epasControl", "EPB_epasEACAllow", "present", "'restart the car' permanent steer fault"),
  C("CORE", "Cruise / TACC state", "DI_state", "DI_cruiseState", "enum", "cruise available / engaged (pcmCruise)",
    need=("STANDBY", "ENABLED")),
  C("CORE", "Cruise set speed", "DI_state", "DI_cruiseSet", "cont", "set speed"),
  C("CORE", "Speed units", "DI_state", "DI_speedUnits", "present", "set-speed units"),
  C("CORE", "Cruise stalk (all moves)", "STW_ACTN_RQ", "SpdCtrlLvr_Stat", "enum",
    "engage (pull), cancel (push), resume, +/- 1st and 2nd detent, AP1 hold gestures",
    need=("FWD", "RWD", "UP_1ST", "DN_1ST", "UP_2ND", "DN_2ND")),
  C("CORE", "Turn signal lever", "STW_ACTN_RQ", "TurnIndLvr_Stat", "enum", "blinker button events (lane change)",
    need=("LEFT", "RIGHT")),
  C("CORE", "Turn signal lights left", "GTW_carState", "BC_indicatorLStatus", "enum", "leftBlinker", need=("1",)),
  C("CORE", "Turn signal lights right", "GTW_carState", "BC_indicatorRStatus", "enum", "rightBlinker", need=("1",)),
  C("CORE", "Seat belt (driver)", "SDM1", "SDM_bcklDrivStatus", "enum", "seat-belt-unlatched alert"),
  C("CORE", "Door front left", "GTW_carState", "DOOR_STATE_FL", "enum", "door-open alert"),
  C("CORE", "Door front right", "GTW_carState", "DOOR_STATE_FR", "enum", "door-open alert"),
  C("CORE", "Door rear left", "GTW_carState", "DOOR_STATE_RL", "enum", "door-open alert"),
  C("CORE", "Door rear right", "GTW_carState", "DOOR_STATE_RR", "enum", "door-open alert"),
  C("CORE", "Frunk (counts as a door)", "GTW_carState", "DOOR_STATE_FrontTrunk", "enum", "door-open alert"),
  C("CORE", "Trunk (counts as a door)", "GTW_carState", "BOOT_STATE", "enum", "door-open alert"),
  C("CORE", "Stock DAS control (bus 2)", "DAS_control", "DAS_accState", "present", "stock ACC state, stock AEB passthrough"),
  C("OPTIONAL", "Blind spot LEFT (0x399)", "AutopilotStatus", "DAS_blindSpotRearLeft", "enum",
    "blind-spot lane-change block, 'Car Detected in Blindspot', Blind Spot Path", need=("WARNING_LEVEL_1|WARNING_LEVEL_2",)),
  C("OPTIONAL", "Blind spot RIGHT (0x399)", "AutopilotStatus", "DAS_blindSpotRearRight", "enum",
    "blind-spot lane-change block, 'Car Detected in Blindspot', Blind Spot Path", need=("WARNING_LEVEL_1|WARNING_LEVEL_2",)),
  C("OPTIONAL", "Follow-distance stalk twist", "STW_ACTN_RQ", "DTR_Dist_Rq", "enum", "stalk follow distance (FrogPilot following)"),
  C("OPTIONAL", "Fused speed limit (0x399)", "AutopilotStatus", "DAS_fusedSpeedLimit", "cont", "dashboard speed limit / speed-limit controller"),
  C("OPTIONAL", "Map speed limit", "UI_driverAssistMapData", "UI_mapSpeedLimit", "cont", "dashboard speed limit (fallback)"),
  C("OPTIONAL", "MPP speed limit", "UI_gpsVehicleSpeed", "UI_mppSpeedLimit", "cont", "dashboard speed limit (fallback)"),
  C("OPTIONAL", "Stock cluster: AutopilotStatus", "AutopilotStatus", "DAS_statusCounter", "present", "AP1 cluster substitution"),
  C("OPTIONAL", "Stock cluster: DAS_status2", "DAS_status2", "DAS_status2Counter", "present", "AP1 cluster substitution"),
  C("OPTIONAL", "Stock cluster: DAS_lanes", "DAS_lanes", "DAS_lanesCounter", "present", "AP1 cluster substitution"),
  C("OPTIONAL", "Stock DAS_steeringControl (0x488)", "DAS_steeringControl", "DAS_steeringControlCounter", "present",
    "steering-counter handover continuity"),
  # FUTURE: not read by BogPilot yet; planned features, cheap to capture now.
  C("FUTURE", "Wiper stalk position", "STW_ACTN_RQ", "WprSw6Posn", "enum",
    "planned: rain-aware following distance / curve speed",
    need=("INTERVAL1|INTERVAL2|INTERVAL3|INTERVAL4|STAGE1|STAGE2",)),
  C("FUTURE", "Auto-wipers setting", "MCU_chassisControl", "MCU_enableAutowipers", "present",
    "planned: rain-aware following distance / curve speed"),
  C("FUTURE", "Stock AP wiper request (bus 2)", "DAS_bodyControls", "DAS_wiperSpeed", "present",
    "planned: rain-aware following distance / curve speed"),
  C("FUTURE", "High beams on", "BODY_R1", "HiBm_On", "enum",
    "planned: at night roll SLC speed offset back (~2 mph lower bands, ~3 mph higher)", need=("1",)),
  C("FUTURE", "High-beam stalk", "STW_ACTN_RQ", "HiBmLvr_Stat", "enum",
    "planned: night detection for SLC speed offset", need=("HIBM_ON_PSD|HIBM_FLSH_ON_PSD",)),
  C("FUTURE", "Stock AP auto high-beam decision (bus 2)", "DAS_bodyControls", "DAS_highLowBeamDecision", "present",
    "planned: night detection for SLC speed offset"),
]
BSM_ADDR = 0x399
BSM_WARNING = (1, 2)   # WARNING_LEVEL_1 / WARNING_LEVEL_2 (3 = SNA), as BogPilot blindspot.py


# ----------------------------------------------------------------------------------------------
# Collection
# ----------------------------------------------------------------------------------------------

class Collector:
  def __init__(self, want_stats, enum_watch):
    self.want_stats = want_stats
    self.enum_watch = enum_watch                    # {(bus, addr): [(sig_key, Signal)]}
    self.lens = collections.defaultdict(set)        # (kind, bus, addr) -> {len}
    self.count = collections.Counter()
    self.seg_first = {}
    self.seg_last = {}
    self.seg_n = collections.Counter()
    self.seg_rates = collections.defaultdict(list)
    self.prev = {}
    self.changed = collections.defaultdict(int)     # little-endian bit mask of bits that ever changed
    self.bmin, self.bmax = {}, {}
    self.distinct = collections.defaultdict(set)
    self.flagged = {}                               # (kind,bus,addr) -> reason
    self.enum_vals = collections.defaultdict(set)
    self.tx_echo = 0
    self.vin_frags = []
    self.zero_seen = set()
    self.vin_pages = {}

  def set_vin(self, vin):
    if vin and len(vin) == 17:
      b = vin.encode()
      self.vin_frags = [b[i:i + 5] for i in range(0, 13)]

  def end_segment(self):
    for key, n in self.seg_n.items():
      if n >= 3:
        dt = (self.seg_last[key] - self.seg_first[key]) / 1e9
        if dt > 0.5:
          self.seg_rates[key].append((n - 1) / dt)
    self.seg_first.clear(); self.seg_last.clear(); self.seg_n.clear(); self.prev.clear()

  def frame(self, kind, t, bus, addr, dat):
    key = (kind, bus, addr)
    self.lens[key].add(len(dat))
    self.count[key] += 1
    if key not in self.seg_first:
      self.seg_first[key] = t
    self.seg_last[key] = t
    self.seg_n[key] += 1
    x = int.from_bytes(dat, "little")
    p = self.prev.get(key)
    self.prev[key] = x
    if p is not None and p != x:
      self.changed[key] |= p ^ x
    if addr in (0x2B9, 0x508) and dat and len(self.vin_pages) < 2048:
      self.vin_pages.setdefault((bus, addr, dat[0]), dat)
    w = self.enum_watch.get((bus, addr))
    if w and kind == "can":
      for sk, sig in w:
        if sk.endswith("#zero"):
          if (bus, sk) not in self.zero_seen and sig.decode(x) == 0:
            self.zero_seen.add((bus, sk))
          continue
        s = self.enum_vals[(bus, sk)]
        if len(s) < 64:
          s.add(sig.decode(x))
    # VIN / ASCII screening on distinct payloads (bounded work per address)
    d = self.distinct[key]
    if len(d) < 512 and dat not in d:
      d.add(dat)
      if key not in self.flagged:
        if any(f in dat for f in self.vin_frags):
          self.flagged[key] = "contains part of this car's VIN"
        elif re.search(rb"[0-9A-HJ-NPR-Z]{6}", dat):
          self.flagged[key] = "contains VIN-like ASCII text"
    if self.want_stats and (p is None or p != x):
      mn, mx = self.bmin.get(key), self.bmax.get(key)
      if mn is None:
        self.bmin[key], self.bmax[key] = list(dat), list(dat)
      else:
        for i, c in enumerate(dat):
          if i >= len(mn):
            mn.append(c); mx.append(c)
          elif c < mn[i]:
            mn[i] = c
          elif c > mx[i]:
            mx[i] = c

  def vins_on_can(self):
    """Reassemble VINs that the car broadcasts (0x508 pages 0-2, radar 0x2B9 pages 16-18).
    Used only to find and remove them; never written."""
    found = set()
    for bus in {k[0] for k in self.vin_pages}:
      g = lambda a, m: self.vin_pages.get((bus, a, m))
      p = [g(0x508, 0), g(0x508, 1), g(0x508, 2)]
      if all(p):
        found.add((p[0][1:8] + p[1][1:8] + p[2][1:4]).decode("latin1"))
      p = [g(0x2B9, 16), g(0x2B9, 17), g(0x2B9, 18)]
      if all(p) and len(p[0]) >= 8:
        found.add((p[0][5:8] + p[1][1:8] + p[2][1:8]).decode("latin1"))
    return {v for v in found if re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", v) and set(v) != {"0"}}

  def rate(self, key):
    r = self.seg_rates.get(key)
    return statistics.median(r) if r else None


NICE_RATES = [0.1, 0.2, 0.25, 0.5, 1, 2, 2.5, 4, 5, 10, 12.5, 20, 25, 33, 40, 50, 100, 200]


def round_rate(r):
  if r is None:
    return None
  for n in NICE_RATES:
    if abs(r - n) <= 0.12 * n:
      return n
  return round(r, 1) if r < 10 else round(r)


def rnd(v):
  if isinstance(v, float):
    if math.isnan(v) or math.isinf(v):
      return None
    return round(v, 4)
  return v


# ----------------------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------------------

def main(argv=None):
  ap = argparse.ArgumentParser(description="Make a privacy-safe BogPilot car fingerprint from your own rlogs "
                                           "(runs locally, uploads nothing).")
  ap.add_argument("paths", nargs="+", help="route folder (with <route>--N segment folders) or rlog / rlog.zst / rlog.bz2 files")
  ap.add_argument("-o", "--output", default="my_car_fingerprint.json", help="output file (default: my_car_fingerprint.json)")
  ap.add_argument("--zip", action="store_true", help="also write the JSON inside a .zip next to it")
  ap.add_argument("--include-can-stats", action="store_true",
                  help="add per-address changing-bit masks and per-byte min/max (no raw frames, no timestamps)")
  ap.add_argument("--force", action="store_true", help="write even if the final privacy self-check finds something (review first!)")
  ap.add_argument("--schema-dir", default=str(HERE / "schema"), help="cereal schema folder (default: bundled)")
  ap.add_argument("--dbc-dir", default=str(HERE / "dbc"), help="folder with tesla_can.dbc / tesla_powertrain.dbc (coverage report)")
  ap.add_argument("--no-coverage", action="store_true", help="skip the recording-checklist coverage report")
  args = ap.parse_args(argv)

  files = find_rlogs(args.paths)
  log = load_schema(args.schema_dir)

  # coverage setup (DBC known for legacy Tesla)
  dbcs = {}
  if not args.no_coverage:
    for bus, fn in TESLA_BUS_DBC.items():
      p = Path(args.dbc_dir) / fn
      if p.exists():
        dbcs.setdefault(fn, parse_dbc(p))
  enum_watch = collections.defaultdict(list)
  for bus, fn in TESLA_BUS_DBC.items():
    if fn not in dbcs:
      continue
    msgs, _ = dbcs[fn]
    for it in CHECKLIST:
      for addr, m in msgs.items():
        if m["name"] == it["msg"] and it["sig"] in m["signals"] and it["kind"] in ("enum", "zero"):
          pair = (f"{it['msg']}.{it['sig']}" + ("#zero" if it["kind"] == "zero" else ""), m["signals"][it["sig"]])
          if pair[0] not in [x[0] for x in enum_watch[(bus, addr)]]:
            enum_watch[(bus, addr)].append(pair)

  col = Collector(args.include_can_stats, enum_watch)
  car_params, init, panda_types, panda_safety, harness, can_speeds = [], None, set(), set(), set(), {}
  periph_types = set()
  services_seen = set()
  print(f"Reading {len(files)} rlog file(s) ...", file=sys.stderr)

  # first pass over carParams to learn the VIN (used only to *find and remove* it; never written)
  secrets = set()
  for i, f in enumerate(files):
    for w, evt in iter_events(log, f):
      services_seen.add(w)
      if w == "carParams":
        cp = evt.carParams
        car_params.append(cp)
        vin = getattr(cp, "carVin", "") or ""
        if vin and set(vin) != {"0"}:
          secrets.add(vin); col.set_vin(vin)
      elif w == "initData" and init is None:
        init = evt.initData
      elif w == "can" or w == "sendcan":
        t = evt.logMonoTime
        for fr in getattr(evt, w):
          src = fr.src
          if w == "can" and src >= 128:
            col.tx_echo += 1
            continue
          col.frame(w, t, src % 128, fr.address, bytes(fr.dat))
      elif w == "pandaStates":
        for ps in evt.pandaStates:
          panda_types.add(str(ps.pandaType)); harness.add(str(ps.harnessStatus))
          panda_safety.add((str(ps.safetyModel), int(ps.safetyParam)))
          for b in range(3):
            try:
              cs = getattr(ps, f"canState{b}")
              can_speeds[b] = (int(cs.canSpeed), int(cs.canDataSpeed), bool(cs.canfdEnabled))
            except Exception:
              pass
      elif w == "pandaStateDEPRECATED":
        panda_types.add(str(evt.pandaStateDEPRECATED.pandaType))
      elif w == "peripheralState":
        periph_types.add(str(evt.peripheralState.pandaType))
    col.end_segment()
    print(f"  {i + 1}/{len(files)} {f.name}", file=sys.stderr)

  can_vins = col.vins_on_can()
  col.can_vins_found = len(can_vins)
  secrets |= can_vins
  # identifiers from initData: only used to make sure they do NOT end up in the output
  if init is not None:
    for fld in ("dongleId", "bootlogId"):
      v = getattr(init, fld, "") if hasattr(init, fld) else ""
      if v and v not in ("UnregisteredDevice",):
        secrets.add(str(v))
    try:
      for a in init.kernelArgs:
        m = re.search(r"serialno=(\S+)", a)
        if m:
          secrets.add(m.group(1))
    except Exception:
      pass
    try:
      pi = init.pandaInfo
      if pi.dongleId:
        secrets.add(str(pi.dongleId))
    except Exception:
      pass

  redactions = []
  out = {"tool": "bogpilot_fingerprint", "tool_version": TOOL_VERSION,
         "privacy": "No VIN, GPS/location, timestamps, device/user IDs, camera/microphone/driver data, params or log text. "
                    "CAN payload bytes are not included" + (" (only per-byte min/max and changing-bit masks, see can_stats)." if args.include_can_stats else ".")}

  # ---- route summary (no times)
  out["route"] = {"segments_read": len(files)}

  # ---- carParams
  if car_params:
    cp = car_params[-1]
    names = sorted({str(c.carFingerprint) for c in car_params})
    g = lambda n: rnd(getattr(cp, n)) if hasattr(cp, n) else None
    cpd = {
      "carName": str(cp.carName), "carFingerprint": str(cp.carFingerprint),
      "fingerprintSource": str(cp.fingerprintSource), "fuzzyFingerprint": bool(cp.fuzzyFingerprint),
      "mass": g("mass"), "wheelbase": g("wheelbase"), "steerRatio": g("steerRatio"), "centerToFront": g("centerToFront"),
      "steerControlType": str(cp.steerControlType), "openpilotLongitudinalControl": bool(cp.openpilotLongitudinalControl),
      "pcmCruise": bool(cp.pcmCruise), "radarUnavailable": bool(cp.radarUnavailable), "enableBsm": bool(cp.enableBsm),
      "networkLocation": str(cp.networkLocation), "transmissionType": str(cp.transmissionType),
      "dashcamOnly": bool(cp.dashcamOnly), "flags": int(cp.flags),
      "minEnableSpeed": g("minEnableSpeed"), "minSteerSpeed": g("minSteerSpeed"),
      "steerActuatorDelay": g("steerActuatorDelay"),
      "safetyConfigs": [{"safetyModel": str(s.safetyModel), "safetyParam": int(s.safetyParam)} for s in cp.safetyConfigs],
    }
    if len(names) > 1:
      cpd["carFingerprint_all_seen"] = names
    out["carParams"] = cpd
    fws, seen = [], set()
    for fw in cp.carFw:
      raw = bytes(fw.fwVersion)
      txt, notes = redact_text(bytes_repr(raw), secrets)
      if notes:
        redactions.append(f"firmware of {fw.ecu} @0x{int(fw.address):x}: {', '.join(sorted(set(notes)))} removed")
      e = {"ecu": str(fw.ecu), "address": f"0x{int(fw.address):x}", "subAddress": int(fw.subAddress) or None,
           "responseAddress": f"0x{int(fw.responseAddress):x}", "bus": int(fw.bus), "brand": str(fw.brand),
           "request": [bytes(r).hex() for r in fw.request], "fwVersion": txt, "redacted": bool(notes)}
      k = json.dumps(e, sort_keys=True)
      if k not in seen:
        seen.add(k); fws.append(e)
    out["carFw"] = fws
  else:
    out["carParams"] = None
    out["carFw"] = []

  # ---- software
  if init is not None:
    remote = str(init.gitRemote or "")
    m = re.search(r"(?:github\.com|gitlab\.com)[:/]+([^/]+)/([^/.\s]+)", remote)
    host = "github.com" if "github.com" in remote else ("gitlab.com" if "gitlab.com" in remote else "other")
    owner, repo = (m.group(1), m.group(2)) if m else (None, None)
    public = bool(owner) and owner.lower() in PUBLIC_OWNERS
    sw = {"version": str(init.version), "deviceType": str(init.deviceType), "dirty": bool(init.dirty),
          "osVersion": str(getattr(init, "osVersion", "") or "") or None,
          "remote": f"{host}/{owner}/{repo}" if public else (f"{host}/<personal fork>/{repo}" if repo else "<not public / unknown>"),
          "gitBranch": str(init.gitBranch) if public else "<hidden: not a known public fork>",
          "gitCommit": str(init.gitCommit) if public else "<hidden: not a known public fork>"}
    if not public:
      redactions.append("software: branch/commit/remote owner hidden (fork not on the public list)")
    if any(s.startswith("frogpilot") for s in services_seen) or "frogpilot" in str(init.gitBranch).lower():
      sw["fork_family"] = "FrogPilot-based"
    out["software"] = sw
  else:
    out["software"] = None

  # ---- panda
  out["panda"] = {"hwType": sorted(panda_types | periph_types), "harnessStatus": sorted(harness),
                  "safetyModes_seen": sorted([f"{a}:{b}" for a, b in panda_safety]),
                  "canSpeed_kbps": {str(b): {"can": v[0], "data": v[1], "canfd": v[2]} for b, v in sorted(can_speeds.items())},
                  "firmwareVersion": None}
  if init is not None:
    try:
      if init.pandaInfo.stVersion:
        out["panda"]["firmwareVersion"] = str(init.pandaInfo.stVersion)
    except Exception:
      pass
  if out["panda"]["firmwareVersion"] is None:
    out["panda"]["firmwareVersion_note"] = "not recorded in this log"

  # ---- CAN fingerprint
  fp = {}
  for (kind, bus, addr), lens in sorted(col.lens.items()):
    d = fp.setdefault(kind, {}).setdefault(str(bus), {})
    d[str(addr)] = {"hex": f"0x{addr:x}", "len": sorted(lens)[0] if len(lens) == 1 else sorted(lens),
                    "hz": round_rate(col.rate((kind, bus, addr)))}
  out["can_fingerprint"] = fp
  out["openpilot_FINGERPRINTS_style"] = {f"bus{bus}": {str(addr): max(col.lens[("can", b, addr)])
                                                       for (k, b, addr) in sorted(col.lens) if k == "can" and b == bus}
                                         for bus in sorted({b for (k, b, a) in col.lens if k == "can"})}

  # ---- withheld addresses
  withheld = {}
  for key in col.lens:
    kind, bus, addr = key
    why = None
    if addr in STATS_DENYLIST:
      why = STATS_DENYLIST[addr]
    elif DIAG_RANGE[0] <= addr <= DIAG_RANGE[1]:
      why = "diagnostic (UDS) range"
    elif key in col.flagged:
      why = col.flagged[key]
    if why:
      withheld[key] = why

  # ---- optional stats
  if args.include_can_stats:
    st = {}
    for key in sorted(col.lens):
      kind, bus, addr = key
      if key in withheld or key not in col.bmin:
        continue
      n = max(col.lens[key])
      chg = col.changed.get(key, 0)
      st.setdefault(kind, {}).setdefault(str(bus), {})[f"0x{addr:x}"] = {
        "changing_bits": [f"{(chg >> (8 * i)) & 0xFF:08b}"[::-1] for i in range(n)],
        "byte_min": col.bmin[key][:n], "byte_max": col.bmax[key][:n]}
    out["can_stats"] = st
    out["can_stats_note"] = ("changing_bits: one string per byte, bit 0 first ('1' = this bit changed at least once). "
                             "Withheld addresses are listed in can_stats_withheld.")
    out["can_stats_withheld"] = sorted({f"0x{a:x}: {w}" for (k, b, a), w in withheld.items()})

  # ---- coverage (Tesla DBC)
  coverage, bsm = [], {}
  if dbcs and (not car_params or str(car_params[-1].carName) == "tesla"):
    for it in CHECKLIST:
      mname, sname, found = it["msg"], it["sig"], None
      for bus, fn in TESLA_BUS_DBC.items():
        if fn not in dbcs:
          continue
        msgs, vals = dbcs[fn]
        for addr, m in msgs.items():
          if m["name"] != mname or sname not in m["signals"]:
            continue
          key = ("can", bus, addr)
          if key not in col.lens:
            continue
          sig = m["signals"][sname]
          entry = {"tier": it["tier"], "step": it["step"], "enables": it["feature"], "signal": f"{mname}.{sname}",
                   "address": f"0x{addr:x}", "bus": bus, "seen": True, "changed": bool(col.changed.get(key, 0) & sig.mask)}
          if it["kind"] == "enum":
            vs = sorted(col.enum_vals.get((bus, f"{mname}.{sname}"), set()))
            names = vals.get((addr, sname), {})
            entry["values"] = [names.get(v, v) for v in vs]
            got = {str(v) for v in entry["values"]}
            missing = [n for n in it["need"] if not any(x in got for x in n.split("|"))]
            if missing:
              entry["missing_values"] = missing
          elif it["kind"] == "zero":
            entry["reached_zero"] = (bus, f"{mname}.{sname}#zero") in col.zero_seen
          entry["kind"] = it["kind"]
          if found is None or (entry["changed"] and not found["changed"]):
            found = entry
      if found is None:
        found = {"tier": it["tier"], "step": it["step"], "enables": it["feature"], "signal": f"{mname}.{sname}",
                 "seen": False, "changed": False}
      k = it["kind"]
      if k == "present":
        found["ok"] = found["seen"]
      elif k == "zero":
        found["ok"] = found["seen"] and bool(found.get("reached_zero"))
      else:
        found["ok"] = found["seen"] and found["changed"] and not found.get("missing_values")
      coverage.append(found)
    # core: fingerprint / firmware / radar
    radar_frames = sum(1 for (k, b, a) in col.lens if k == "can" and b == 1)
    extra = [
      {"tier": "CORE", "step": "CAN fingerprint", "enables": "car recognition", "signal": "all buses",
       "seen": bool(col.lens), "changed": True, "ok": bool(col.lens)},
      {"tier": "CORE", "step": "Firmware versions (carFw)", "enables": "car recognition (FW fingerprint)", "signal": "carParams.carFw",
       "seen": bool(out.get("carFw")), "changed": True, "ok": bool(out.get("carFw"))},
      {"tier": "CORE", "step": "Radar frames on bus 1", "enables": "lead car for openpilot longitudinal (radar)", "signal": "bus 1",
       "seen": radar_frames > 0, "changed": radar_frames > 0, "addresses": radar_frames,
       "ok": radar_frames > 0 or not (out.get("carParams") or {}).get("openpilotLongitudinalControl", False)},
    ]
    coverage = extra + coverage
    # explicit 0x399 blind-spot report
    for (kind, bus, addr), lens in sorted(col.lens.items()):
      if addr == BSM_ADDR and kind == "can":
        vl = col.enum_vals.get((bus, "AutopilotStatus.DAS_blindSpotRearLeft"), set())
        vr = col.enum_vals.get((bus, "AutopilotStatus.DAS_blindSpotRearRight"), set())
        bsm[str(bus)] = {"len": sorted(lens), "hz": round_rate(col.rate((kind, bus, addr))),
                         "left_warning_seen": any(v in BSM_WARNING for v in vl) if (bus in (0, 2)) else None,
                         "right_warning_seen": any(v in BSM_WARNING for v in vr) if (bus in (0, 2)) else None,
                         "left_values": sorted(vl), "right_values": sorted(vr)}
    core_missing = [c["step"] for c in coverage if c["tier"] == "CORE" and not c["ok"]]
    out["coverage"] = {"dbc": "BogPilot opendbc tesla_can.dbc / tesla_powertrain.dbc",
                       "core_sufficient_for_basic_port": not core_missing, "core_missing": core_missing,
                       "checklist": coverage, "blind_spot_0x399": bsm or "0x399 not seen on any bus"}

  if redactions:
    out["redactions"] = sorted(set(redactions))

  text = json.dumps(out, indent=1, sort_keys=False, ensure_ascii=True)

  # ---- final privacy self-check
  hits = privacy_scan(text, secrets)

  # ---- summary
  print_summary(out, col, withheld, hits, args)

  if hits and not args.force:
    print("\nNOT WRITTEN: the privacy self-check found something that looks personal (listed above).\n"
          "Look at it, and only if you are sure it is harmless re-run with --force.", file=sys.stderr)
    return 2
  outp = Path(args.output).expanduser()
  outp.write_text(text + "\n")
  print(f"\nWrote {outp} ({outp.stat().st_size / 1024:.1f} KB)")
  if args.zip:
    zp = outp.with_suffix(".zip")
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
      zi = zipfile.ZipInfo(outp.name, date_time=(1980, 1, 1, 0, 0, 0))
      zi.compress_type = zipfile.ZIP_DEFLATED
      z.writestr(zi, text + "\n")
    print(f"Wrote {zp} ({zp.stat().st_size / 1024:.1f} KB)")
  print("Nothing was uploaded. Attach the file to a BogPilot GitHub issue yourself if you want to share it.")
  return 0


def privacy_scan(text, secrets):
  hits = []
  def add(kind, s):
    hits.append(f"{kind}: '{s[:3]}…' ({len(s)} chars)")
  for sec in secrets:
    if not sec:
      continue
    low = text.lower()
    if sec.lower() in low:
      add("known identifier from the log", sec)
    elif len(sec) == 17:
      for i in range(0, 11):
        frag = sec[i:i + 7]
        if frag.lower() in low:
          add("fragment of this car's VIN", frag); break
  for m in VIN_TOKEN.finditer(text):
    if looks_like_vin(m.group(0)):
      add("VIN-like text", m.group(0))
  for m in COORD_RE.finditer(text):
    try:
      a, b = float(m.group(1)), float(m.group(2))
    except ValueError:
      continue
    if -90 <= a <= 90 and -180 <= b <= 180 and (abs(a) > 1 or abs(b) > 1):
      add("coordinate-like number pair", m.group(0))
  for rx, kind in ((EMAIL_RE, "email"), (IPV4_RE, "IP address"), (MAC_RE, "MAC address"),
                   (LONG_NUMBER, "long number"), (WORDS_RE, "identifier keyword")):
    for m in rx.finditer(text):
      add(kind, m.group(0))
  return hits


def print_summary(out, col, withheld, hits, args):
  P = print
  P("\n" + "=" * 72)
  P(" BogPilot car fingerprint - exactly what the output file contains")
  P("=" * 72)
  cp = out.get("carParams")
  if cp:
    P(f" Car (as detected by openpilot): {cp['carName']} / {cp['carFingerprint']}  (source: {cp['fingerprintSource']})")
    P(f"   mass {cp['mass']} kg, wheelbase {cp['wheelbase']} m, steerRatio {cp['steerRatio']}, steer {cp['steerControlType']}, "
      f"op long {cp['openpilotLongitudinalControl']}, BSM {cp['enableBsm']}, radar {'no' if cp['radarUnavailable'] else 'yes'}")
    P(f"   safety: {', '.join(s['safetyModel'] + ':' + str(s['safetyParam']) for s in cp['safetyConfigs'])}")
  else:
    P(" carParams: not found in these logs")
  P(f" Firmware versions: {len(out['carFw'])} ECU entries" + (f" ({sum(e['redacted'] for e in out['carFw'])} redacted)" if out['carFw'] else ""))
  for e in out["carFw"]:
    P(f"   {e['ecu']:<22} {e['address']:<6} {e['brand']:<8} {e['fwVersion']}")
  sw = out.get("software")
  if sw:
    P(f" Software: version {sw['version']}, {sw['remote']}, branch {sw['gitBranch']}, device {sw['deviceType']}")
  pa = out["panda"]
  P(f" Panda: {', '.join(pa['hwType']) or '?'}; safety modes seen {', '.join(pa['safetyModes_seen']) or '?'}; "
    f"firmware {pa['firmwareVersion'] or 'not recorded'}")
  for kind, buses in out["can_fingerprint"].items():
    for bus, addrs in buses.items():
      P(f" CAN {kind:<7} bus {bus}: {len(addrs):>3} addresses (address, length, rate only)")
  if "can_stats" in out:
    n = sum(len(a) for b in out["can_stats"].values() for a in b.values())
    P(f" CAN stats: {n} addresses with changing-bit masks + per-byte min/max (no raw frames, no times)")
    P(f"   withheld (never exported): {len(out['can_stats_withheld'])} addresses")
    for w in out["can_stats_withheld"]:
      P(f"     {w}")
  if "coverage" in out:
    cov = out["coverage"]
    tier_note = {"CORE": " (needed for a basic port)", "OPTIONAL": " (extra BogPilot features)",
                 "FUTURE": " (planned BogPilot features, nice to capture now; not required)"}
    for tier in ("CORE", "OPTIONAL", "FUTURE"):
      P(f" Recording checklist coverage - {tier}{tier_note[tier]}:")
      for c in cov["checklist"]:
        if c["tier"] != tier:
          continue
        if not c["seen"]:
          mark = "MISSING"
        elif c["ok"]:
          mark = "ok"
        elif c.get("kind") == "zero":
          mark = "never 0"
        elif not c["changed"]:
          mark = "no change"
        else:
          mark = "partial"
        extra = ""
        if c.get("values"):
          extra += f" values {c['values']}"
        if c.get("missing_values"):
          extra += f" - still needed: {c['missing_values']}"
        P(f"   [{mark:>9}] {c['step']:<34} -> {c['enables']}{extra}")
    b = cov["blind_spot_0x399"]
    if isinstance(b, dict):
      for bus, v in b.items():
        P(f"   0x399 AutopilotStatus on bus {bus}: len {v['len']}, ~{v['hz']} Hz, "
          f"left warning seen: {v['left_warning_seen']}, right warning seen: {v['right_warning_seen']}")
    else:
      P(f"   0x399: {b}")
    if cov["core_sufficient_for_basic_port"]:
      P(" VERDICT: all CORE items were captured - this log is sufficient for a basic port.")
    else:
      P(f" VERDICT: NOT sufficient for a basic port yet - missing/incomplete CORE items: {', '.join(cov['core_missing'])}.")
      P("          Record another drive following the README checklist for those items.")
  for r in out.get("redactions", []):
    P(f" Redacted: {r}")
  if getattr(col, "can_vins_found", 0):
    P(f" The car broadcasts its VIN on CAN ({col.can_vins_found} found); it was used only to check the output and is NOT included.")
  P(" Removed entirely: VIN, GPS/location, navigation, timestamps, device/user IDs, camera/microphone/driver-camera")
  P("   data, params, log text, network info, raw CAN payloads" + (" (except stats above)" if "can_stats" in out else ""))
  if col.tx_echo:
    P(f" (ignored {col.tx_echo} panda transmit-echo frames)")
  P("-" * 72)
  if hits:
    P(" PRIVACY SELF-CHECK: FOUND POSSIBLE PERSONAL DATA:")
    for h in hits[:30]:
      P(f"   ! {h}")
  else:
    P(" Privacy self-check: passed (no VIN, coordinates, email, IP, MAC, IDs or long numbers found)")


if __name__ == "__main__":
  sys.exit(main())
