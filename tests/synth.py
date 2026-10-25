"""Build small synthetic rlogs for tests (no real drive data).

Every CAN address/length/signal used here comes from the bundled dbc/tesla_can.dbc or from the
hardware table in bogpilot_fingerprint.py (which cites BogGyver/opendbc and commaai/opendbc).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import bogpilot_fingerprint as bf  # noqa: E402

LOG = bf.load_schema(str(ROOT / "schema"))
CAN_MSGS, CAN_VALS = bf.parse_dbc(ROOT / "dbc" / "tesla_can.dbc")
NAME2ADDR = {m["name"]: a for a, m in CAN_MSGS.items()}


def encode(addr, values, length=None):
  """Encode {signal: raw int} into a payload using the bundled DBC bit layout."""
  m = CAN_MSGS[addr]
  n = length or m["len"]
  x = 0
  for sname, raw in values.items():
    sig = m["signals"][sname]
    raw &= (1 << sig.size) - 1
    for i, b in enumerate(sig.bits):             # sig.bits is MSB first
      if (raw >> (sig.size - 1 - i)) & 1:
        x |= 1 << b
  return x.to_bytes(8, "little")[:n]


def val(addr, sname, label):
  for k, v in CAN_VALS.get((addr, sname), {}).items():
    if v == label:
      return k
  raise KeyError((addr, sname, label))


# chassis-bus checklist messages (no DAS): (message, [signal -> list of raw values to cycle through])
def chassis_script(epb=True, moving=False):
  """epb: include EPB_epasControl (0x214), which an AP1 car sends but a pre-AP car does not.
  moving: speed never 0 (for the moving-window tests)."""
  A = NAME2ADDR
  gear = A["DI_torque2"]; stw = A["STW_ACTN_RQ"]; brk = A["BrakeMessage"]; dis = A["DI_state"]
  cyc = {
    "ESP_B": {"ESP_vehicleSpeed": [100, 400] if moving else [0, 100, 400, 0]},
    "DI_torque2": {"DI_gear": [val(gear, "DI_gear", g) for g in ("DI_GEAR_P", "DI_GEAR_R", "DI_GEAR_N", "DI_GEAR_D")]},
    "DI_torque1": {"DI_pedalPos": [0, 50, 120]},
    "BrakeMessage": {"driverBrakeStatus": [val(brk, "driverBrakeStatus", "NOT_APPLIED"), val(brk, "driverBrakeStatus", "APPLIED")]},
    "EPAS_sysStatus": {"EPAS_internalSAS": [100, 2000, 8000], "EPAS_torsionBarTorque": [100, 900, 2000],
                       "EPAS_handsOnLevel": [0, 1, 2], "EPAS_eacStatus": [0, 1, 2], "EPAS_eacErrorCode": [0]},
    "STW_ANGLHP_STAT": {"StW_AnglHP_Spd": [10, 300, 900]},
    "EPB_epasControl": {"EPB_epasEACAllow": [1]},
    "DI_state": {"DI_cruiseState": [val(dis, "DI_cruiseState", "STANDBY"), val(dis, "DI_cruiseState", "ENABLED")],
                 "DI_cruiseSet": [50, 70], "DI_speedUnits": [1]},
    "STW_ACTN_RQ": {"SpdCtrlLvr_Stat": [val(stw, "SpdCtrlLvr_Stat", s) for s in ("IDLE", "FWD", "RWD", "UP_1ST", "DN_1ST", "UP_2ND", "DN_2ND")],
                    "TurnIndLvr_Stat": [val(stw, "TurnIndLvr_Stat", s) for s in ("IDLE", "LEFT", "RIGHT")]},
    "GTW_carState": {"BC_indicatorLStatus": [0, 1], "BC_indicatorRStatus": [0, 1], "DOOR_STATE_FL": [0, 1],
                     "DOOR_STATE_FR": [0, 1], "DOOR_STATE_RL": [0, 1], "DOOR_STATE_RR": [0, 1],
                     "DOOR_STATE_FrontTrunk": [0, 1], "BOOT_STATE": [0, 1]},
    "SDM1": {"SDM_bcklDrivStatus": [0, 1]},
  }
  if not epb:
    del cyc["EPB_epasControl"]
  return {A[n]: s for n, s in cyc.items()}


def frames_for(script, i):
  out = []
  for addr, sigs in script.items():
    out.append((addr, encode(addr, {s: v[i % len(v)] for s, v in sigs.items()})))
  return out


def write_rlog(path, *, car_name="tesla", fingerprint="TESLA_AP1_MODELS", buses, n=40, sendcan=None, with_fw=True,
               params=None, safety_model=None):
  """buses: {bus: callable(i) -> [(addr, bytes)]}; a key >= 128 is written as that src (panda transmit echo).
  params: {name: bytes} written to initData.params. safety_model: raw int for pandaStates/carParams safetyConfigs
  (37 = NotAutopilot teslaPreap, unknown to the bundled schema). Writes an uncompressed rlog."""
  evts = []
  if params is not None:
    ie = LOG.Event.new_message(logMonoTime=0)
    en = ie.init("initData").init("params").init("entries", len(params))
    for k, (name, v) in enumerate(params.items()):
      en[k].key = name; en[k].value = v
    evts.append(ie)
  cp = LOG.Event.new_message(logMonoTime=1)
  c = cp.init("carParams"); c.carName = car_name; c.carFingerprint = fingerprint
  if with_fw:
    fw = c.init("carFw", 1)[0]
    fw.ecu = "eps"; fw.address = 0x730; fw.fwVersion = b"TEST-EPAS-FW"; fw.brand = "tesla"
  if safety_model is not None:
    sc = c.init("safetyConfigs", 1)[0]
    sc.safetyModel = safety_model
    pe = LOG.Event.new_message(logMonoTime=2)
    pe.init("pandaStates", 1)[0].safetyModel = safety_model
    evts.append(pe)
  evts.append(cp)
  for i in range(n):
    t = 1_000_000_000 + i * 100_000_000          # 10 Hz, 4 s total
    e = LOG.Event.new_message(logMonoTime=t)
    frs = [(b, a, d) for b, fn in buses.items() for a, d in fn(i)]
    lst = e.init("can", len(frs))
    for j, (b, a, d) in enumerate(frs):
      lst[j].address = a; lst[j].dat = d; lst[j].src = b
    evts.append(e)
    if sendcan:
      s = LOG.Event.new_message(logMonoTime=t + 1)
      frs = [(b, a, d) for b, fn in sendcan.items() for a, d in fn(i)]
      lst = s.init("sendcan", len(frs))
      for j, (b, a, d) in enumerate(frs):
        lst[j].address = a; lst[j].dat = d; lst[j].src = b
      evts.append(s)
  Path(path).write_bytes(b"".join(e.to_bytes() for e in evts))
  return path


def pre_ap_buses(radar=True, pedal=True, ibooster=True, unknown=True, chassis_bus=0, radar_bus=1, pedal_bus=2,
                 epb=False, fp_hints=True, moving=False):
  """A pre-AP car as Tinkla/NotAutopilot wire it: chassis on 0, radar on 1, pedal on 2; no 0x214 from the car."""
  script = chassis_script(epb=epb, moving=moving)
  extra = []
  if ibooster:
    extra += [(0x39D, bytes(4)), (0x554, bytes(5))]    # IBST_status 4, ECU_BrakeStatus 5 (BogGyver/opendbc)
  if unknown:
    extra.append((0x4F7, bytes(3)))                    # deliberately unknown, not in any bundled/cited DBC
  if fp_hints:
    extra += [(0x505, bytes(8)), (0x227, bytes(4))]    # pre-AP fingerprint entries (BogGyver/openpilot values.py)
  buses = {chassis_bus: lambda i: frames_for(script, i) + [(a, bytes([i % 256]) + d[1:]) for a, d in extra]}
  if pedal:
    pb = buses.get(pedal_bus)
    gas = lambda i: [(0x552, bytes([i % 256]) + bytes(5))]   # GAS_SENSOR, 6 bytes (BogGyver/opendbc tesla_can.dbc)
    buses[pedal_bus] = (lambda i: pb(i) + gas(i)) if pb else gas
  if radar:
    # Bosch radar status + one track pair (commaai/opendbc tesla_radar_bosch_generated.dbc), all 8 bytes
    buses[radar_bus] = lambda i: [(0x301, bytes(8)), (0x302, bytes(8)), (0x501, bytes([i % 256]) + bytes(7)),
                                  (0x310, bytes(8)), (0x311, bytes(8))]
  return buses
