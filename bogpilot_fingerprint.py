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
TOOL_VERSION = "1.2.0"

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
  # 0x32D IBST_info: iBooster build/PCBA/assembly ids and firmware CRCs (ECU identifiers, like firmware versions).
  # Source: BogGyver/opendbc 9c0b6fe tesla_can.dbc#L1170-L1180.
  0x32D: "iBooster part/CRC identifiers (IBST_info, iBooster)",
  # 0x405 VIN_VIP_405HS: chassis-side VIN on cars without 0x508 (pre-AP); the panda copies it 1:1 to the radar as
  # 0x2B9. Sources: BogGyver/openpilot 0d99a1b panda/board/safety/safety_tesla.h#L489-L496,
  # BogGyver/opendbc 9c0b6fe tesla_radar.dbc#L1162 (mux pages 16-18 = VIN).
  0x405: "VIN (VIN_VIP_405HS, chassis bus on pre-AP cars)",
  # 0x2A9: GTW_carConfig copy sent to the radar (country code like 0x398). Sources: BogGyver/opendbc 9c0b6fe
  # tesla_radar.dbc#L1168; BogGyver/openpilot 0d99a1b panda/board/safety/safety_tesla.h#L498-L514 (0x398 -> 0x2A9).
  0x2A9: "car configuration / country code sent to the radar (GTW_carConfig copy, radar bus)",
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
DEFAULT_BUS_ROLES = {0: "chassis", 1: "radar", 2: "chassis", 4: "powertrain", 6: "powertrain"}
# Pre-AP default (used only when the profile is pre-ap and no --bus-map was given): chassis on 0, Bosch radar on 1,
# pedal interceptor on 2. Tinkla and NotAutopilot both put the pedal on CAN2 by default (or CAN0 if chosen).
# Sources: NotAutopilot/opendbc cc39c7f opendbc/car/tesla/preap/carstate.py#L178-L198 (pedal bus param, default 2);
#          BogGyver/openpilot 0d99a1b panda/board/safety/safety_tesla.h#L1055-L1060 (pedal bus learnt from 0x552 on 0 or 2).
PREAP_DEFAULT_BUS_ROLES = {0: "chassis", 1: "radar", 2: "other"}
ROLE_DBC = {"chassis": "tesla_can.dbc", "powertrain": "tesla_powertrain.dbc"}
BUS_ROLES = ("chassis", "powertrain", "radar", "other")


def parse_bus_map(text):
  """'0=chassis,1=radar,2=powertrain' -> {0: 'chassis', 1: 'radar', 2: 'powertrain'}"""
  roles = {}
  for part in filter(None, (x.strip() for x in text.split(","))):
    m = re.fullmatch(r"(\d+)\s*=\s*(\w+)", part)
    if not m or m.group(2) not in BUS_ROLES or not 0 <= int(m.group(1)) <= 127:
      raise argparse.ArgumentTypeError(f"bad --bus-map entry '{part}' (use BUS=ROLE, ROLE one of {', '.join(BUS_ROLES)})")
    roles[int(m.group(1))] = m.group(2)
  return roles


# ---- Pre-AP / custom hardware
# Messages sent only by the factory Autopilot ECU (DAS), names from the bundled tesla_can.dbc. A pre-AP Model S
# (2012-2014, no AP hardware) has no DAS, so none of these appear on its chassis bus. 0x2B9/0x209 are only
# counted on non-radar buses, because on the radar bus the same addresses carry VIN/odometer to the radar.
DAS_MSGS = {"DAS_control", "DAS_steeringControl", "DAS_lanes", "DAS_longControl", "AutopilotStatus", "DAS_status2",
            "DAS_bodyControls"}
# AP1 needs BOTH of these received on bus 0/2 (or a bus mapped as chassis), never on a radar bus. One alone is not
# enough; the other DAS messages above are reported as supporting evidence only. Same rule as NotAutopilot's
# auto-detection: NotAutopilot/opendbc 21a45cf opendbc/car/tesla/nap_detect.py#L9 (AP_ECU_ADDRS), #L21-L28.
# Address/length: bundled dbc/tesla_can.dbc line 67 (BO_ 1160 DAS_steeringControl: 4) and line 74 (BO_ 697
# DAS_control: 8); same in BogGyver/opendbc 9c0b6fe tesla_can.dbc#L896 and #L420.
AP1_REQUIRED = {0x488: 4, 0x2B9: 8}
# Chassis/body messages every 2012+ Model S sends (no AP hardware needed). Used to recognise a Tesla chassis bus
# even when openpilot did not identify the car (carName 'mock'). Names from the bundled tesla_can.dbc.
# EPB_epasControl (0x214) is deliberately NOT here: it is missing from the factory pre-AP fingerprint and on pre-AP
# cars it is sent by the comma (BogGyver/openpilot 0d99a1b selfdrive/car/tesla/values.py#L57-L62;
# NotAutopilot/opendbc cc39c7f opendbc/car/tesla/fingerprints.py#L89-L95).
TESLA_BODY_MSGS = ("ESP_B", "DI_torque1", "DI_torque2", "STW_ACTN_RQ", "STW_ANGLHP_STAT", "GTW_carState",
                   "EPAS_sysStatus", "BrakeMessage", "DI_state", "SDM1")
TESLA_BODY_MIN = 6        # this many of TESLA_BODY_MSGS (address + length) on one bus = Tesla chassis bus
# Optional fingerprint hints (reported only, never decide the profile). The Tinkla/NAP pre-AP CAN fingerprint has
# 0x505 at 8 bytes and 0x227 at 4 bytes; the AP1 fingerprints have 0x227 at 5 bytes.
# Sources: BogGyver/openpilot 0d99a1b selfdrive/car/tesla/values.py#L39-L46 (AP1) vs #L57-L62 (pre-AP);
#          NotAutopilot/opendbc cc39c7f opendbc/car/tesla/fingerprints.py#L89-L95.
FP_HINTS = [(0x505, 8, "pre-ap"), (0x227, 4, "pre-ap"), (0x227, 5, "ap1")]
# GTW_carConfig (0x398) on the chassis bus: only GTW_dasHw and GTW_autopilot are decoded, as a hint. The payload is
# never stored and 0x398 stays on the stats denylist. Bit layout from the bundled dbc/tesla_can.dbc line 409
# (BO_ 920), line 413 (GTW_dasHw : 7|2@0+) and line 432 (GTW_autopilot : 61|2@0+). dasHw != 0 means DAS hardware is
# fitted: BogGyver/openpilot 0d99a1b panda/board/safety/safety_tesla.h#L498-L514 ((byte0 & 0xC0) > 0 -> has_das_hw).
GTW_CARCONFIG = 0x398
# ESP_B.ESP_vehicleSpeed (0x155) decides how long the car was moving (bundled dbc/tesla_can.dbc lines 206/209).
SPEED_SNA_RAW = 0xFFFF
PREAP_WINDOW_S = 60       # default seconds of driving with no factory AP messages before calling it pre-AP

# Retrofit hardware recognised by address + length only (payloads are never decoded for this).
# Sources: commaai/opendbc opendbc/dbc/tesla_radar_bosch_generated.dbc (removed after 551081b, Nov 2024);
#          BogGyver/opendbc tesla_can.dbc @ 9c0b6fe (Tinkla pre-AP port: pedal interceptor, iBooster).
BOSCH_RADAR_STATUS = {0x301: 8, 0x302: 8, 0x501: 8}   # TeslaRadarSguInfo, TeslaRadarTguInfo, TeslaRadarAlertMatrix
BOSCH_RADAR_POINTS = frozenset([
  0x310, 0x311, 0x313, 0x314, 0x316, 0x317, 0x319, 0x31A, 0x31C, 0x31D, 0x31F, 0x320, 0x322, 0x323, 0x325, 0x326,
  0x328, 0x329, 0x32B, 0x32C, 0x32E, 0x32F, 0x331, 0x332, 0x334, 0x335, 0x337, 0x338, 0x33A, 0x33B, 0x33D, 0x33E,
  0x340, 0x341, 0x343, 0x344, 0x346, 0x347, 0x349, 0x34A, 0x34C, 0x34D, 0x34F, 0x350, 0x352, 0x353, 0x355, 0x356,
  0x358, 0x359, 0x35B, 0x35C, 0x35E, 0x35F, 0x361, 0x362, 0x364, 0x365, 0x367, 0x368, 0x36A, 0x36B, 0x36D, 0x36E,
  0x371, 0x372, 0x374, 0x375, 0x377, 0x378, 0x37A, 0x37B, 0x37D, 0x37E])   # RadarPoint0_A .. RadarPoint31_B
# Bosch radar state on a radar bus, by address only (no DBC gives their length): 0x300 = radar active/heartbeat,
# 0x631 = radar init (it lies in the UDS range but is not hidden from this check on a radar bus).
# Sources: BogGyver/openpilot 0d99a1b panda/board/safety/safety_tesla.h#L856-L880; NotAutopilot/openpilot e99f4dc
# scripts/nap/diagnose_radar.py (watches 0x631 init -> 0x300 active).
RADAR_ACTIVE, RADAR_INIT = 0x300, 0x631
RETROFIT_HW = [
  {"id": "radar", "label": "Tesla Bosch radar", "all": BOSCH_RADAR_STATUS,
   "source": "commaai/opendbc tesla_radar_bosch_generated.dbc (0x301 TeslaRadarSguInfo, 0x302 TeslaRadarTguInfo, 0x501 TeslaRadarAlertMatrix)"},
  {"id": "pedal", "label": "comma pedal interceptor", "any": {0x552: 6},
   "source": "BogGyver/opendbc tesla_can.dbc#L910 (0x552 GAS_SENSOR)"},
  # Only the retrofit iBooster ECU / IVS board messages prove a retrofit. Sources: BogGyver/opendbc 9c0b6fe
  # tesla_can.dbc#L917 (0x554 ECU_BrakeStatus: 5), #L937 (0x556 IVS_Status: 6).
  {"id": "ibooster", "label": "Bosch iBooster (retrofit ECU)", "any": {0x554: 5, 0x556: 6},
   "source": "BogGyver/opendbc tesla_can.dbc#L917 (0x554 ECU_BrakeStatus), #L937 (0x556 IVS_Status)"},
]
# IBST_* messages come from the iBooster itself. They are FACTORY on AP1 cars (the AP1 fingerprint has them and the
# Tinkla panda detects the factory iBooster from 0x39D), and count as a retrofit only on a pre-AP car.
# Sources: BogGyver/opendbc 9c0b6fe tesla_can.dbc#L1182 (0x39D IBST_status: 4), #L1170 (0x32D IBST_info: 4),
#          #L946 (0x35D IBST_dtcMatrix: 4); BogGyver/openpilot 0d99a1b panda/board/safety/safety_tesla.h#L850-L853,
#          selfdrive/car/tesla/values.py#L39-L46 (AP1 fingerprint).
IBST_MSGS = {0x39D: 4, 0x32D: 4, 0x35D: 4}
# commands the comma itself sends to that hardware (seen in sendcan)
# Sources: BogGyver/opendbc 9c0b6fe tesla_can.dbc#L903 (0x551 GAS_COMMAND: 6), #L926 (0x553 ECU_BrakeCommand: 6),
#          #L933 (0x555 IVS_Command: 6); commaai/panda 39671c3 board/pedal/main.c#L94-L95 (stock comma pedal
#          firmware uses 0x200 command / 0x201 sensor).
RETROFIT_TX = {0x551: ("pedal", 6, "GAS_COMMAND"), 0x553: ("ibooster", 6, "ECU_BrakeCommand"),
               0x555: ("ibooster", 6, "IVS_Command"), 0x200: ("pedal", 6, "GAS_COMMAND (stock comma pedal ID)")}
# Stock comma pedal firmware IDs received at 6 bytes on a non-chassis bus: 0x201 clashes with SDM1 (0x201, 5 bytes).
# Sources: commaai/panda 39671c3 board/pedal/main.c#L94-L95; NotAutopilot/opendbc cc39c7f
# opendbc/car/tesla/preap/carstate.py#L102 ("SDM1 (0x201) collides with Comma Pedal").
STOCK_PEDAL_IDS = {0x200: 6, 0x201: 6}
# what the user may declare with --hw (fixed words only, so nothing personal can be typed into the output)
DECLARABLE_HW = ("radar", "pedal", "ibooster", "epas-firmware", "harness", "other")

# Recording-checklist signals, in three tiers. CORE/OPTIONAL list only signals BogPilot's legacy-Tesla code actually reads
# (selfdrive/car/tesla/carstate.py, values.py BUTTONS/DOORS, cluster.py, blindspot.py).
# CORE = needed for a basic port; OPTIONAL = extra BogPilot features; FUTURE = planned BogPilot features.
# kind: "enum"    small state values; lists the values seen, "need" = values that must appear
#       "cont"    continuous value; must change at least once
#       "zero"    continuous value; must reach 0 at least once (standstill)
#       "present" message must be present (no change expected)
def C(tier, step, msg, sig, kind, feature, need=(), when=None):
  return {"tier": tier, "step": step, "msg": msg, "sig": sig, "kind": kind, "feature": feature, "need": list(need), "when": when,
          "das": msg in DAS_MSGS}

# Checklist messages a pre-AP car does not send itself (n/a there), with the reason shown in the report.
# 0x214: not in the factory pre-AP fingerprint; Tinkla/NAP send it from the comma (sources at TESLA_BODY_MSGS).
PREAP_NA = {"EPB_epasControl": "not sent by a pre-AP car (Tinkla/NAP send 0x214 from the comma)"}

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

def vin_from_mux_pages(p16, p17, p18):
  """VIN_VIP_405HS layout (0x405 on the chassis bus, 0x2B9 on the radar bus): mux byte 0, page 16 carries VIN
  characters 1-3 in bytes 5-7, pages 17 and 18 carry 7 characters each in bytes 1-7.
  Source: BogGyver/opendbc 9c0b6fe tesla_radar.dbc#L1162-L1166. Used only to find and remove the VIN."""
  if not (p16 and p17 and p18) or len(p16) < 8:
    return None
  return (p16[5:8] + p17[1:8] + p18[1:8]).decode("latin1")


# GTW_carConfig signals used as a hint (see GTW_CARCONFIG above); big-endian (@0) as in the bundled DBC
GTW_DASHW_SIG = Signal("GTW_dasHw", 7, 2, False, False)
GTW_AUTOPILOT_SIG = Signal("GTW_autopilot", 61, 2, False, False)
ESP_SPEED_SIG = Signal("ESP_vehicleSpeed", 47, 16, False, False)


class Collector:
  def __init__(self, want_stats, enum_watch, speed_addr=None):
    self.want_stats = want_stats
    self.enum_watch = enum_watch                    # {(bus, addr): [(sig_key, Signal)]}
    self.speed_addr = speed_addr                    # ESP_B address (from the bundled DBC), or None
    self.speed_t = {}                               # bus -> last ESP_B time (ns)
    self.moving_ns = collections.Counter()          # bus -> ns with ESP_vehicleSpeed > 0
    self.speed_ns = collections.Counter()           # bus -> ns covered by ESP_B frames
    self.gtw_dashw = collections.defaultdict(set)   # bus -> GTW_dasHw values (hint only)
    self.gtw_autopilot = collections.defaultdict(set)
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
    self.seg_first.clear(); self.seg_last.clear(); self.seg_n.clear(); self.prev.clear(); self.speed_t.clear()

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
    if addr in (0x2B9, 0x508, 0x405) and dat and len(self.vin_pages) < 2048:
      self.vin_pages.setdefault((bus, addr, dat[0]), dat)
    if kind == "can":
      if addr == self.speed_addr and len(dat) == 8:
        last = self.speed_t.get(bus)
        self.speed_t[bus] = t
        if last is not None and t > last:
          dt = min(t - last, 1_000_000_000)        # gaps (dropped frames, segment joins) count at most 1 s
          self.speed_ns[bus] += dt
          v = ESP_SPEED_SIG.decode(x)
          if 0 < v < SPEED_SNA_RAW:
            self.moving_ns[bus] += dt
      elif addr == GTW_CARCONFIG and len(dat) == 8:
        if len(self.gtw_dashw[bus]) < 4:
          self.gtw_dashw[bus].add(GTW_DASHW_SIG.decode(x))
        if len(self.gtw_autopilot[bus]) < 4:
          self.gtw_autopilot[bus].add(GTW_AUTOPILOT_SIG.decode(x))
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
    """Reassemble VINs that the car broadcasts (0x508 pages 0-2; 0x405 (pre-AP chassis) and radar 0x2B9 pages
    16-18). Used only to find and remove them; never written."""
    found = set()
    for bus in {k[0] for k in self.vin_pages}:
      g = lambda a, m: self.vin_pages.get((bus, a, m))
      p = [g(0x508, 0), g(0x508, 1), g(0x508, 2)]
      if all(p):
        found.add((p[0][1:8] + p[1][1:8] + p[2][1:4]).decode("latin1"))
      for a in (0x2B9, 0x405):
        v = vin_from_mux_pages(g(a, 16), g(a, 17), g(a, 18))
        if v:
          found.add(v)
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


# Safety models newer than the bundled cereal schema. pycapnp cannot name them (str() raises), which used to stop
# the tool on NotAutopilot logs. Source: NotAutopilot/opendbc cc39c7f opendbc/car/car.capnp#L645-L646
# (teslaLegacy @36, teslaPreap @37) and opendbc/safety/declarations.h#L38 (SAFETY_TESLA_PREAP 37U).
SAFETY_MODEL_EXTRA = {36: "teslaLegacy", 37: "teslaPreap"}
SAFETY_TESLA_PREAP = 37


def enum_str(v, extra=None):
  """str() of a capnp enum, or a readable fallback for values the bundled schema does not know."""
  try:
    return str(v)
  except Exception:
    raw = int(getattr(v, "raw", -1))
    return (extra or {}).get(raw, f"unknown({raw})")


# Fork settings that mean "this car was set up as pre-AP" (reported as hints; the values are compared with fixed
# strings and never written). Sources:
#   NotAutopilot: param NAPForcePreAP forces TESLA_MODEL_S_PREAP (NotAutopilot/opendbc cc39c7f
#     opendbc/car/car_helpers.py#L90-L99; default 1 in NotAutopilot/openpilot e99f4dc common/params_keys.h#L136);
#     param NAPCarType 1 = Pre-AP (NotAutopilot/opendbc 21a45cf opendbc/car/tesla/nap_detect.py#L11-L14);
#     platform TESLA_MODEL_S_PREAP (NotAutopilot/opendbc cc39c7f opendbc/car/tesla/values.py#L113).
#   Tinkla: param TinklaAPForceFingerprint (BogGyver/openpilot 0d99a1b selfdrive/car/tesla/carstate.py#L113,
#     interface.py#L41); platform 'TESLA PREAP MODEL S' (selfdrive/car/tesla/values.py#L18).
PREAP_FINGERPRINTS = {"TESLA_MODEL_S_PREAP": "NotAutopilot", "TESLA PREAP MODEL S": "Tinkla"}
PREAP_PARAMS = {"NAPForcePreAP": (b"1", "NotAutopilot param NAPForcePreAP=1 (forces TESLA_MODEL_S_PREAP; NAP default)"),
                "NAPCarType": (b"1", "NotAutopilot param NAPCarType=1 (Pre-AP)"),
                "TinklaAPForceFingerprint": (b"TESLA PREAP MODEL S", "Tinkla param TinklaAPForceFingerprint='TESLA PREAP MODEL S'")}


def fork_hints(car_params, safety_raw, init):
  hints = []
  for c in car_params:
    fork = PREAP_FINGERPRINTS.get(str(c.carFingerprint))
    h = f"{fork} carFingerprint {c.carFingerprint}"
    if fork and h not in hints:
      hints.append(h)
  if SAFETY_TESLA_PREAP in safety_raw:
    hints.append("NotAutopilot safety model teslaPreap (37)")
  if init is not None:
    try:
      for e in init.params.entries:
        want = PREAP_PARAMS.get(str(e.key))
        if want and bytes(e.value).strip() == want[0] and want[1] not in hints:
          hints.append(want[1])
    except Exception:
      pass
  return hints


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
  ap.add_argument("--car-profile", choices=("auto", "ap1", "ap2", "pre-ap"), default="auto",
                  help="auto (default): ap1 when both factory AP1 messages 0x488 and 0x2B9 are received on bus 0/2; pre-ap "
                       "when a Tesla chassis bus shows no factory Autopilot messages at all; otherwise 'unknown' (then "
                       "choose one). ap1: factory AP1 hardware; ap2: AP2/AP2.5 (manual only, AP2 messages are not modelled "
                       "yet); pre-ap: 2012-2014 Model S without factory AP hardware")
  ap.add_argument("--preap-window", type=float, default=PREAP_WINDOW_S, metavar="SECONDS",
                  help=f"seconds of driving with no factory AP messages for a confident pre-AP result (default "
                       f"{PREAP_WINDOW_S}; shorter logs are judged on the whole log and marked low confidence)")
  ap.add_argument("--hw", default="", help=f"comma list of retrofit hardware you added, from: {', '.join(DECLARABLE_HW)} "
                                           "(recorded in the file and compared with what the log shows)")
  ap.add_argument("--bus-map", type=parse_bus_map, default=None,
                  help="which panda bus carries what, e.g. '0=chassis,1=radar,2=powertrain' (roles: chassis, powertrain, "
                       "radar, other). Default: BogPilot AP1 layout 0=chassis,1=radar,2=chassis,4=powertrain,6=powertrain; for a "
                       "pre-AP car 0=chassis,1=radar,2=other (pedal bus)")
  args = ap.parse_args(argv)
  declared_hw = sorted({h.strip().lower() for h in args.hw.split(",") if h.strip()})
  bad = [h for h in declared_hw if h not in DECLARABLE_HW]
  if bad:
    ap.error(f"--hw: unknown item(s) {', '.join(bad)}; use only: {', '.join(DECLARABLE_HW)}")
  bus_roles = dict(args.bus_map) if args.bus_map else dict(DEFAULT_BUS_ROLES)
  bus_dbc = {b: ROLE_DBC[r] for b, r in sorted(bus_roles.items()) if r in ROLE_DBC}

  files = find_rlogs(args.paths)
  log = load_schema(args.schema_dir)

  # coverage setup (DBC known for legacy Tesla). The DBCs are also needed for the vehicle profile, so they are
  # loaded even with --no-coverage (which then only skips the coverage report).
  dbcs = {}
  for fn in sorted(set(TESLA_BUS_DBC.values())):
    p = Path(args.dbc_dir) / fn
    if p.exists():
      dbcs.setdefault(fn, parse_dbc(p))
  cov_dbcs = {} if args.no_coverage else dbcs
  # watch signals on every bus that may end up mapped as chassis/powertrain (the pre-AP default map is only
  # chosen after reading, so collect for both default layouts and any --bus-map)
  watch_dbc = dict(TESLA_BUS_DBC)
  watch_dbc.update(bus_dbc)
  enum_watch = collections.defaultdict(list)
  for bus, fn in watch_dbc.items():
    if fn not in cov_dbcs:
      continue
    msgs, _ = dbcs[fn]
    for it in CHECKLIST:
      for addr, m in msgs.items():
        if m["name"] == it["msg"] and it["sig"] in m["signals"] and it["kind"] in ("enum", "zero"):
          pair = (f"{it['msg']}.{it['sig']}" + ("#zero" if it["kind"] == "zero" else ""), m["signals"][it["sig"]])
          if pair[0] not in [x[0] for x in enum_watch[(bus, addr)]]:
            enum_watch[(bus, addr)].append(pair)

  speed_addr = next((a for a, m in dbcs.get("tesla_can.dbc", ({}, {}))[0].items() if m["name"] == "ESP_B"), None)
  col = Collector(args.include_can_stats, enum_watch, speed_addr)
  safety_raw = set()
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
          panda_types.add(enum_str(ps.pandaType)); harness.add(enum_str(ps.harnessStatus))
          panda_safety.add((enum_str(ps.safetyModel, SAFETY_MODEL_EXTRA), int(ps.safetyParam)))
          safety_raw.add(int(ps.safetyModel.raw))
          for b in range(3):
            try:
              cs = getattr(ps, f"canState{b}")
              can_speeds[b] = (int(cs.canSpeed), int(cs.canDataSpeed), bool(cs.canfdEnabled))
            except Exception:
              pass
      elif w == "pandaStateDEPRECATED":
        panda_types.add(enum_str(evt.pandaStateDEPRECATED.pandaType))
      elif w == "peripheralState":
        periph_types.add(enum_str(evt.peripheralState.pandaType))
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
      "safetyConfigs": [{"safetyModel": enum_str(s.safetyModel, SAFETY_MODEL_EXTRA), "safetyParam": int(s.safetyParam)}
                        for s in cp.safetyConfigs],
    }
    if len(names) > 1:
      cpd["carFingerprint_all_seen"] = names
    out["carParams"] = cpd
    fws, seen = [], set()
    for fw in cp.carFw:
      raw = bytes(fw.fwVersion)
      txt, notes = redact_text(bytes_repr(raw), secrets)
      if notes:
        redactions.append(f"firmware of {enum_str(fw.ecu)} @0x{int(fw.address):x}: {', '.join(sorted(set(notes)))} removed")
      e = {"ecu": enum_str(fw.ecu), "address": f"0x{int(fw.address):x}", "subAddress": int(fw.subAddress) or None,
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

  # ---- vehicle profile (AP1 / pre-AP / unknown) and retrofit hardware
  for c in car_params:
    for sc in c.safetyConfigs:
      safety_raw.add(int(sc.safetyModel.raw))
  hints = fork_hints(car_params, safety_raw, init)
  prof = vehicle_profile(col, dbcs, bus_roles, args.car_profile, declared_hw, hints=hints,
                         bus_map_given=bool(args.bus_map), window_s=args.preap_window)
  bus_roles = prof["bus_roles"]
  bus_dbc = {b: ROLE_DBC[r] for b, r in sorted(bus_roles.items()) if r in ROLE_DBC}
  out["vehicle_profile"] = prof["profile_out"]
  out["retrofit_hardware"] = prof["hw_out"]
  pre_ap = prof["profile"] == "pre-ap"
  dbcs = cov_dbcs

  # ---- coverage (Tesla DBC)
  coverage, bsm = [], {}
  car_name = str(car_params[-1].carName) if car_params else None
  is_tesla = car_name in (None, "tesla") or prof["tesla_chassis_bus"] is not None or args.car_profile != "auto"
  if dbcs and car_name not in (None, "tesla") and is_tesla:
    out["vehicle_profile"]["note"] = (f"openpilot did not identify this car as a Tesla (carName '{car_name}'); the coverage "
                                      "report was made from the Tesla chassis CAN messages in the log.")
  if dbcs and is_tesla:
    for it in CHECKLIST:
      mname, sname, found = it["msg"], it["sig"], None
      na_reason = None
      if pre_ap and it["das"]:
        na_reason = "sent by the factory Autopilot ECU (DAS), which a pre-AP car does not have"
      elif pre_ap and mname in PREAP_NA:
        na_reason = PREAP_NA[mname]
      elif prof["profile"] == "ap2" and it["das"]:
        na_reason = "AP2 messages are not modelled yet; real AP2 logs are needed"
      if na_reason:
        coverage.append({"tier": it["tier"], "step": it["step"], "enables": it["feature"], "signal": f"{mname}.{sname}",
                         "seen": False, "changed": False, "ok": True, "na": True, "na_reason": na_reason})
        continue
      for bus, fn in bus_dbc.items():
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
    radar_buses = prof["radar_buses"]
    radar_frames = sum(1 for (k, b, a) in col.lens if k == "can" and b in radar_buses)
    extra = [
      {"tier": "CORE", "step": "CAN fingerprint", "enables": "car recognition", "signal": "all buses",
       "seen": bool(col.lens), "changed": True, "ok": bool(col.lens)},
      {"tier": "CORE", "step": "Firmware versions (carFw)", "enables": "car recognition (FW fingerprint)", "signal": "carParams.carFw",
       "seen": bool(out.get("carFw")), "changed": True, "ok": bool(out.get("carFw"))},
      {"tier": "CORE", "step": "Radar frames on bus " + ("/".join(map(str, sorted(radar_buses))) or "1"),
       "enables": "lead car for openpilot longitudinal (radar)", "signal": "bus " + ("/".join(map(str, sorted(radar_buses))) or "1"),
       "seen": radar_frames > 0, "changed": radar_frames > 0, "addresses": radar_frames,
       "ok": radar_frames > 0 or not (out.get("carParams") or {}).get("openpilotLongitudinalControl", False)},
    ]
    coverage = extra + coverage
    # explicit 0x399 blind-spot report
    for (kind, bus, addr), lens in sorted(col.lens.items()):
      if addr == BSM_ADDR and kind == "can":
        mapped = bus_dbc.get(bus) == "tesla_can.dbc"     # values only from buses the map used treats as chassis DBC
        vl = col.enum_vals.get((bus, "AutopilotStatus.DAS_blindSpotRearLeft"), set()) if mapped else set()
        vr = col.enum_vals.get((bus, "AutopilotStatus.DAS_blindSpotRearRight"), set()) if mapped else set()
        bsm[str(bus)] = {"len": sorted(lens), "hz": round_rate(col.rate((kind, bus, addr))),
                         "left_warning_seen": any(v in BSM_WARNING for v in vl) if bus_roles.get(bus) == "chassis" else None,
                         "right_warning_seen": any(v in BSM_WARNING for v in vr) if bus_roles.get(bus) == "chassis" else None,
                         "left_values": sorted(vl), "right_values": sorted(vr)}
    core_missing = [c["step"] for c in coverage if c["tier"] == "CORE" and not c["ok"]]
    out["coverage"] = {"dbc": "BogPilot opendbc tesla_can.dbc / tesla_powertrain.dbc", "profile": prof["profile"],
                       "core_sufficient_for_basic_port": not core_missing, "core_missing": core_missing,
                       "checklist": coverage,
                       "blind_spot_0x399": bsm or ("not expected: pre-AP cars have no factory blind-spot (DAS) message" if pre_ap
                                                   else "0x399 not seen on any bus")}

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


def vehicle_profile(col, dbcs, bus_roles, requested, declared_hw, hints=(), bus_map_given=False, window_s=PREAP_WINDOW_S):
  """Decide the car type (ap1 / pre-ap / unknown, or what --car-profile says) and, separately, find retrofit hardware
  and addresses that no bundled DBC knows. Uses (bus, address, length) of received CAN only; the only payload bits
  read are ESP_vehicleSpeed (how long the car moved) and GTW_dasHw/GTW_autopilot (hint). Frames the comma sent
  itself (sendcan, and src>=128 transmit echoes, which are dropped while reading) never count as car evidence.
  Retrofit hardware never decides the car type."""
  rx = collections.defaultdict(dict)                       # bus -> {addr: max len}
  for (kind, bus, addr), lens in col.lens.items():
    if kind == "can":
      rx[bus][addr] = max(lens)
  tx = {(bus, addr): max(lens) for (kind, bus, addr), lens in col.lens.items() if kind == "sendcan"}
  chassis = dbcs.get("tesla_can.dbc", ({}, {}))[0]
  powertrain = dbcs.get("tesla_powertrain.dbc", ({}, {}))[0]
  by_name = {m["name"]: (a, m["len"]) for a, m in chassis.items()}

  # Tesla chassis bus: enough always-present body messages with the right length
  body = [by_name[n] for n in TESLA_BODY_MSGS if n in by_name]
  body_hits = {bus: sum(1 for a, n in body if seen.get(a) == n) for bus, seen in rx.items()}
  tesla_bus = max(body_hits, key=lambda b: (body_hits[b], -b)) if body_hits else None
  if tesla_bus is not None and body_hits[tesla_bus] < TESLA_BODY_MIN:
    tesla_bus = None

  # Bosch radar (address + length), on any bus. Any bus mapped or detected as radar is skipped for AP1 evidence.
  detected, radar_buses = [], {b for b, r in bus_roles.items() if r == "radar"}
  radar_hw = RETROFIT_HW[0]
  for bus, seen in sorted(rx.items()):
    if all(seen.get(a) == n for a, n in radar_hw["all"].items()):
      radar_buses.add(bus)
      addrs = sorted(radar_hw["all"]) + sorted(a for a in seen if a in BOSCH_RADAR_POINTS)
      detected.append({"id": "radar", "label": radar_hw["label"], "bus": bus, "addresses": [f"0x{a:x}" for a in addrs],
                       "source": radar_hw["source"]})

  # ---- car type: factory AP1 evidence (received only, bus 0/2 or a bus mapped as chassis, never a radar bus)
  ap_buses = ({0, 2} | {b for b, r in bus_roles.items() if r == "chassis"}) - radar_buses
  ap1_ids = {a: sorted(b for b in ap_buses if rx.get(b, {}).get(a) == n) for a, n in AP1_REQUIRED.items()}
  das_addrs = {a for a, m in chassis.items() if m["name"] in DAS_MSGS}
  das_seen = sorted({(b, a) for b in ap_buses for a in rx.get(b, {}) if a in das_addrs})
  dashw = sorted(set().union(*[col.gtw_dashw.get(b, set()) for b in ap_buses])) if ap_buses else []
  autopilot = sorted(set().union(*[col.gtw_autopilot.get(b, set()) for b in ap_buses])) if ap_buses else []
  fp_hints = [f"0x{a:x} len {n} ({p} fingerprint)" for a, n, p in FP_HINTS
              if tesla_bus is not None and rx[tesla_bus].get(a) == n]
  speed_bus = tesla_bus if tesla_bus is not None else 0
  moving_s = round(col.moving_ns.get(speed_bus, 0) / 1e9, 1)
  logged_s = round(col.speed_ns.get(speed_bus, 0) / 1e9, 1)
  das_txt = ", ".join(f"0x{a:x}@bus{b}" for b, a in das_seen[:6])
  confidence = None

  if requested != "auto":
    profile, reason = requested, "set with --car-profile"
  elif all(ap1_ids.values()):
    profile = "ap1"
    reason = ("factory AP1 messages 0x488 DAS_steeringControl and 0x2B9 DAS_control received on bus " +
              "/".join(str(b) for b in sorted(set(ap1_ids[0x488]) | set(ap1_ids[0x2B9]))) +
              (f"; other factory Autopilot (DAS) messages seen: {das_txt}" if das_seen else "") +
              ". An AP2 car sends these too (BogGyver/openpilot values.py#L36): use --car-profile ap2 for AP2")
  elif das_seen:
    have = [f"0x{a:x}" for a, b in ap1_ids.items() if b]
    profile = "unknown"
    reason = (f"only part of the factory AP1 messages were received ({das_txt}); AP1 needs both 0x488 and 0x2B9 on bus "
              f"0/2{' (have ' + ', '.join(have) + ')' if have else ''}. Please choose --car-profile")
  elif tesla_bus is None:
    profile, reason = "unknown", "no Tesla chassis bus recognised in this log. Please choose --car-profile (or check --bus-map)"
  elif any(v != 0 for v in dashw):
    profile = "unknown"
    reason = (f"GTW_carConfig says DAS hardware is fitted (GTW_dasHw {dashw}) but no factory Autopilot messages were "
              "received: an AP1 car with the DAS asleep/unplugged, or AP2 (not modelled). Please choose --car-profile")
  else:
    profile = "pre-ap"
    if moving_s >= window_s:
      confidence = "high"
      basis = f"{moving_s:g} s of driving (window {window_s:g} s)"
    else:
      confidence = "high" if hints else "low"
      basis = (f"the whole log ({moving_s:g} s of driving, {logged_s:g} s logged; shorter than the {window_s:g} s window)"
               + ("; NotAutopilot/Tinkla pre-AP setting found" if hints else ""))
    reason = (f"Tesla chassis messages on bus {tesla_bus} ({body_hits[tesla_bus]}/{len(body)}) and no factory Autopilot "
              f"(DAS) messages received during {basis}")
  if profile == "unknown" and hints:
    reason += f" (the log has NotAutopilot/Tinkla pre-AP settings: if this is a pre-AP car use --car-profile pre-ap)"

  # bus roles actually used: pre-AP default when the car is pre-ap and no --bus-map was given
  if profile == "pre-ap" and not bus_map_given:
    bus_roles = dict(PREAP_DEFAULT_BUS_ROLES)
    radar_buses |= {b for b, r in bus_roles.items() if r == "radar"}
  chassis_buses = {b for b, r in bus_roles.items() if r == "chassis"}

  # ---- retrofit hardware (separate from the car type; address + length)
  for hw in RETROFIT_HW[1:]:
    for bus, seen in sorted(rx.items()):
      addrs = sorted(a for a, n in hw["any"].items() if seen.get(a) == n)
      if addrs:
        detected.append({"id": hw["id"], "label": hw["label"], "bus": bus, "addresses": [f"0x{a:x}" for a in addrs],
                         "source": hw["source"]})
  factory = []
  ibst_src = "BogGyver/opendbc tesla_can.dbc#L1182 (0x39D IBST_status), #L1170 (0x32D IBST_info), #L946 (0x35D IBST_dtcMatrix)"
  for bus, seen in sorted(rx.items()):
    addrs = sorted(a for a, n in IBST_MSGS.items() if seen.get(a) == n)
    if not addrs:
      continue
    if profile == "pre-ap":
      detected.append({"id": "ibooster", "label": "Bosch iBooster (IBST messages; a retrofit on a pre-AP car)", "bus": bus,
                       "addresses": [f"0x{a:x}" for a in addrs], "source": ibst_src})
    else:
      factory.append({"id": "ibooster", "label": "Bosch iBooster IBST messages (factory on AP1; a retrofit only on a "
                      "pre-AP car)", "bus": bus, "addresses": [f"0x{a:x}" for a in addrs], "source": ibst_src})
  hw_hints = []
  for bus, seen in sorted(rx.items()):
    clash = sorted(a for a, n in STOCK_PEDAL_IDS.items() if seen.get(a) == n)
    if clash and bus not in chassis_buses:
      label = "comma pedal with stock comma firmware IDs (clashes with SDM1 0x201)"
      detected.append({"id": "pedal", "label": label, "bus": bus, "addresses": [f"0x{a:x}" for a in clash],
                       "source": "commaai/panda board/pedal/main.c#L94-L95"})
      hw_hints.append(f"bus {bus}: {label}; flash the Tinkla/NAP pedal firmware (0x551/0x552)")
  for (bus, addr), n in sorted(tx.items()):
    if addr in RETROFIT_TX and RETROFIT_TX[addr][1] == n:
      hid, _, name = RETROFIT_TX[addr]
      detected.append({"id": hid, "label": f"comma sends {name} (to {hid})", "bus": bus, "addresses": [f"0x{addr:x}"],
                       "source": "BogGyver/opendbc tesla_can.dbc" if addr != 0x200 else "commaai/panda board/pedal/main.c#L94-L95",
                       "sent_by_comma": True})
  radar_state = {}
  for bus in sorted(radar_buses):
    seen = rx.get(bus, {})
    active, init_ = RADAR_ACTIVE in seen, RADAR_INIT in seen
    if active or init_:
      radar_state[str(bus)] = {"active_0x300": active, "init_0x631": init_}
      if init_ and not active:
        hw_hints.append(f"bus {bus}: radar not syncing (check VIN learn / GTW emulation)")

  # addresses no bundled/cited DBC knows (per bus): aftermarket hardware or undocumented messages
  known = set(chassis) | set(powertrain) | set(STATS_DENYLIST) | set(IBST_MSGS) | set(STOCK_PEDAL_IDS)
  known |= {a for a, _, _ in FP_HINTS} | {RADAR_ACTIVE, RADAR_INIT}
  for hw in RETROFIT_HW:
    known |= set(hw.get("all", {})) | set(hw.get("any", {}))
  unknown = {}
  for bus, seen in sorted(rx.items()):
    u = sorted(a for a in seen if a not in known and not (DIAG_RANGE[0] <= a <= DIAG_RANGE[1])
               and not (bus in radar_buses and a in BOSCH_RADAR_POINTS))
    if u:
      unknown[str(bus)] = [f"0x{a:x}" for a in u]

  # bus-role guess (only to suggest --bus-map; the map actually used is bus_roles)
  bus_dbc = {b: ROLE_DBC[r] for b, r in sorted(bus_roles.items()) if r in ROLE_DBC}
  guess = {}
  for bus, seen in sorted(rx.items()):
    if bus in radar_buses and any(d["id"] == "radar" and d["bus"] == bus for d in detected):
      guess[bus] = "radar"; continue
    sc = sum(1 for a, m in chassis.items() if seen.get(a) == m["len"])
    sp = sum(1 for a, m in powertrain.items() if seen.get(a) == m["len"] and a not in chassis)
    if sc >= TESLA_BODY_MIN and sc >= sp:
      guess[bus] = "chassis"
    elif sp >= 3:
      guess[bus] = "powertrain"
  hint = None
  wrong = [b for b, g in guess.items() if bus_roles.get(b) not in (g, None) or (g in ROLE_DBC and b not in bus_dbc)]
  if wrong:
    hint = ("the log looks like " + ", ".join(f"bus {b}={guess[b]}" for b in sorted(guess)) +
            "; if that is your wiring, re-run with --bus-map " + ",".join(f"{b}={guess[b]}" for b in sorted(guess)))

  detected_ids = {d["id"] for d in detected}
  profile_out = {"profile": profile, "requested": requested, "reason": reason,
                 "bus_roles": {str(b): r for b, r in sorted(bus_roles.items())},
                 "bus_role_guess": {str(b): g for b, g in sorted(guess.items())}}
  if confidence:
    profile_out["confidence"] = confidence
  profile_out["evidence"] = {
    "ap1_0x488_buses": ap1_ids[0x488], "ap1_0x2b9_buses": ap1_ids[0x2B9],
    "das_messages_received": [f"0x{a:x}@bus{b}" for b, a in das_seen],
    "tesla_chassis_bus": tesla_bus, "seconds_moving": moving_s, "seconds_logged": logged_s, "window_seconds": window_s,
    "gtw_dasHw": dashw, "gtw_autopilot": autopilot, "fingerprint_hints": fp_hints,
    "note": "Only frames the car sent count. Frames the comma sent (sendcan, transmit echoes), such as the 0x488/0x2B9/"
            "0x214 that NotAutopilot/Tinkla send, are ignored. AP2 is never chosen automatically."}
  if hints:
    profile_out["fork_preap_hints"] = list(hints)
  if not bus_map_given and profile == "pre-ap":
    profile_out["bus_roles_note"] = "pre-AP default bus map (0=chassis, 1=radar, 2=other/pedal); change it with --bus-map"
  if hint:
    profile_out["bus_map_hint"] = hint
  hw_out = {"detected": detected, "declared": declared_hw,
            "declared_not_seen": [h for h in declared_hw if h in ("radar", "pedal", "ibooster") and h not in detected_ids],
            "unrecognized_addresses": unknown,
            "note": "Recognised by CAN address and length only. Addresses not in the bundled DBCs are still listed in "
                    "can_fingerprint; they are reported here so a developer can see what aftermarket hardware adds."}
  if factory:
    hw_out["factory_hardware"] = factory
  if radar_state:
    hw_out["radar_state"] = radar_state
  if hw_hints:
    hw_out["hints"] = hw_hints
  return {"profile": profile, "profile_out": profile_out, "hw_out": hw_out, "radar_buses": radar_buses,
          "tesla_chassis_bus": tesla_bus, "bus_roles": bus_roles}


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
  vp, hw = out.get("vehicle_profile") or {}, out.get("retrofit_hardware") or {}
  if vp:
    conf = f", confidence {vp['confidence']}" if vp.get("confidence") else ""
    P(f" Vehicle profile: {vp['profile']}{conf} ({vp['reason']})")
    if vp["profile"] == "unknown":
      P("   ! could not tell the car type: re-run with --car-profile ap1, ap2 or pre-ap")
    for h in vp.get("fork_preap_hints", []):
      P(f"   pre-AP hint from the fork settings: {h}")
    for h in (vp.get("evidence") or {}).get("fingerprint_hints", []):
      P(f"   fingerprint hint: {h}")
    P(f"   bus roles used: {', '.join(f'{b}={r}' for b, r in vp['bus_roles'].items())}")
    if vp.get("bus_roles_note"):
      P(f"   ({vp['bus_roles_note']})")
    if vp.get("bus_map_hint"):
      P(f"   hint: {vp['bus_map_hint']}")
    if vp.get("note"):
      P(f"   note: {vp['note']}")
  if hw:
    for d in hw["detected"]:
      P(f" Retrofit hardware seen: {d['label']} on bus {d['bus']} ({', '.join(d['addresses'])})")
    for d in hw.get("factory_hardware", []):
      P(f" Factory hardware seen: {d['label']} on bus {d['bus']} ({', '.join(d['addresses'])})")
    for bus, st in (hw.get("radar_state") or {}).items():
      P(f" Radar on bus {bus}: 0x300 (active) {'seen' if st['active_0x300'] else 'not seen'}, "
        f"0x631 (init) {'seen' if st['init_0x631'] else 'not seen'}")
    for h in hw.get("hints", []):
      P(f"   ! {h}")
    if hw["declared"]:
      P(f" Retrofit hardware you declared (--hw): {', '.join(hw['declared'])}")
    for h in hw["declared_not_seen"]:
      P(f"   ! declared '{h}' but none of its CAN messages were in the log (check wiring / bus, or it is not on CAN)")
    for bus, addrs in hw["unrecognized_addresses"].items():
      P(f" Bus {bus}: {len(addrs)} address(es) not in the bundled Tesla DBCs (aftermarket or undocumented, kept in the "
        f"fingerprint): {', '.join(addrs[:12])}{' ...' if len(addrs) > 12 else ''}")
  if "coverage" in out:
    cov = out["coverage"]
    tier_note = {"CORE": " (needed for a basic port)", "OPTIONAL": " (extra BogPilot features)",
                 "FUTURE": " (planned BogPilot features, nice to capture now; not required)"}
    for tier in ("CORE", "OPTIONAL", "FUTURE"):
      P(f" Recording checklist coverage - {tier}{tier_note[tier]}:")
      for c in cov["checklist"]:
        if c["tier"] != tier:
          continue
        if c.get("na"):
          mark = "n/a"
        elif not c["seen"]:
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
        if c.get("na"):
          extra += f" ({c.get('na_reason') or 'not on this car'})"
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
