"""Tests for pre-AP / custom-hardware handling. Run:  python3 -m unittest discover -s tests -v
Uses synthetic logs only (tests/synth.py); no real drive data."""
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest

import factory_fingerprints
import synth
from synth import bf, NAME2ADDR


BASE_COMMIT = "2719446955e1eaabc4c0ae4da74d81e1faa98d86"   # upstream main this change is based on


def run(rlog_buses, *extra, car_name="tesla", sendcan=None, with_fw=True, mod=None, **kw):
  d = tempfile.mkdtemp()
  p = synth.write_rlog(os.path.join(d, "r--0--rlog"), car_name=car_name, buses=rlog_buses, sendcan=sendcan, with_fw=with_fw,
                       **kw)
  out = os.path.join(d, "fp.json")
  buf = io.StringIO()
  with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
    rc = (mod or bf).main([p, "-o", out, "--schema-dir", str(synth.ROOT / "schema"), "--dbc-dir", str(synth.ROOT / "dbc"),
                           *extra])
  j = None
  if os.path.exists(out):
    with open(out) as f:
      j = json.load(f)
  return rc, j, buf.getvalue()


def ap1_buses(ibooster=True, das=True):
  """An AP1 car: chassis (with 0x214 and the AP1 0x227 length) on 0, factory DAS on 2, radar on 1."""
  b = synth.pre_ap_buses(pedal=False, ibooster=False, unknown=False, epb=True, fp_hints=False)
  chassis = b[0]
  extra = [(0x227, bytes(5))]                                      # AP1 fingerprint length (BogGyver/openpilot values.py)
  if ibooster:
    extra += [(0x39D, bytes(4)), (0x32D, bytes(4)), (0x35D, bytes(4))]   # factory iBooster IBST_* on AP1
  b[0] = lambda i: chassis(i) + extra
  if das:
    b[2] = das_frames
  return b


def spoof(i):
  # what NotAutopilot/Tinkla send from the comma on a pre-AP car: 0x488, 0x2B9 and 0x214 (bundled DBC lengths)
  return [(0x488, bytes(4)), (0x2B9, bytes(8)), (0x214, bytes(3))]


def das_frames(i):
  # factory AP1 DAS messages (addresses/lengths from bundled dbc/tesla_can.dbc)
  return [(NAME2ADDR[n], bytes(synth.CAN_MSGS[NAME2ADDR[n]]["len"]))
          for n in ("DAS_control", "AutopilotStatus", "DAS_status2", "DAS_lanes", "DAS_steeringControl")]


class PreApTests(unittest.TestCase):
  def test_pre_ap_auto_detected_and_verdict_not_blocked_by_das(self):
    rc, j, txt = run(synth.pre_ap_buses())
    self.assertEqual(rc, 0)
    self.assertEqual(j["vehicle_profile"]["profile"], "pre-ap")
    self.assertTrue(j["coverage"]["core_sufficient_for_basic_port"], j["coverage"]["core_missing"])
    das = [c for c in j["coverage"]["checklist"] if c["signal"].startswith("DAS_control.")]
    self.assertTrue(das and das[0]["na"])
    self.assertIn("n/a", txt)

  def test_unrecognised_car_still_gets_coverage_from_tesla_chassis(self):
    rc, j, txt = run(synth.pre_ap_buses(), car_name="mock")
    self.assertEqual(rc, 0)
    self.assertIn("coverage", j)
    self.assertIn("mock", j["vehicle_profile"]["note"])

  def test_retrofit_hardware_detected(self):
    pedal_cmd = lambda i: [(0x551, bytes(6))]   # GAS_COMMAND sent by the comma
    rc, j, _ = run(synth.pre_ap_buses(), "--hw", "radar,pedal,ibooster", sendcan={2: pedal_cmd})
    found = {(d["id"], d["bus"], d.get("sent_by_comma", False)) for d in j["retrofit_hardware"]["detected"]}
    self.assertIn(("radar", 1, False), found)
    self.assertIn(("pedal", 2, False), found)
    self.assertIn(("pedal", 2, True), found)
    self.assertIn(("ibooster", 0, False), found)
    self.assertEqual(j["retrofit_hardware"]["declared_not_seen"], [])
    self.assertEqual(j["retrofit_hardware"]["unrecognized_addresses"], {"0": ["0x4f7"]})
    # extra / unknown messages are kept in the fingerprint and do not break anything
    self.assertIn(str(0x4F7), j["can_fingerprint"]["can"]["0"])
    self.assertTrue(j["coverage"]["core_sufficient_for_basic_port"])

  def test_declared_but_missing_hardware_is_reported(self):
    rc, j, txt = run(synth.pre_ap_buses(radar=False, pedal=False, ibooster=False), "--hw", "radar,pedal,epas-firmware")
    self.assertEqual(j["retrofit_hardware"]["declared"], ["epas-firmware", "pedal", "radar"])
    self.assertEqual(j["retrofit_hardware"]["declared_not_seen"], ["pedal", "radar"])
    self.assertIn("declared 'radar' but none", txt)

  def test_radar_on_other_bus_counts_for_radar_check(self):
    rc, j, _ = run(synth.pre_ap_buses(radar_bus=5))
    radar = [c for c in j["coverage"]["checklist"] if c["step"].startswith("Radar frames")][0]
    self.assertIn("5", radar["step"])
    self.assertTrue(radar["seen"])

  def test_bad_hw_word_rejected(self):
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
      bf.main(["x", "--hw", "my-vin-123"])

  def test_bus_map_override_and_hint(self):
    # chassis wired to bus 3 (not in the default map): hint suggests --bus-map, override makes coverage work
    rc, j, txt = run(synth.pre_ap_buses(chassis_bus=3))
    self.assertIn("--bus-map", j["vehicle_profile"].get("bus_map_hint", ""))
    self.assertFalse(j["coverage"]["core_sufficient_for_basic_port"])
    rc, j, _ = run(synth.pre_ap_buses(chassis_bus=3), "--bus-map", "3=chassis,1=radar")
    self.assertTrue(j["coverage"]["core_sufficient_for_basic_port"], j["coverage"]["core_missing"])
    self.assertEqual(j["vehicle_profile"]["bus_roles"], {"1": "radar", "3": "chassis"})

  def test_pre_ap_default_bus_map_and_0x214_na(self):
    rc, j, txt = run(synth.pre_ap_buses())
    vp = j["vehicle_profile"]
    self.assertEqual(vp["bus_roles"], {"0": "chassis", "1": "radar", "2": "other"})
    self.assertIn("pre-AP default bus map", vp["bus_roles_note"])
    self.assertEqual(vp["confidence"], "low")                    # 4 s log < 60 s window, no fork setting
    self.assertIn("whole log", vp["reason"])
    epb = [c for c in j["coverage"]["checklist"] if c["signal"].startswith("EPB_epasControl.")]
    self.assertTrue(epb and epb[0]["na"] and "0x214" in epb[0]["na_reason"])
    self.assertIn("0x505 len 8 (pre-ap fingerprint)", vp["evidence"]["fingerprint_hints"])
    self.assertIn("0x227 len 4 (pre-ap fingerprint)", vp["evidence"]["fingerprint_hints"])
    self.assertIn("confidence low", txt)

  def test_moving_window(self):
    # 70 s driving at 10 Hz > 60 s window -> high confidence; --preap-window shortens the window
    rc, j, _ = run(synth.pre_ap_buses(moving=True), n=700)
    self.assertEqual(j["vehicle_profile"]["confidence"], "high")
    self.assertGreaterEqual(j["vehicle_profile"]["evidence"]["seconds_moving"], 60)
    rc, j, _ = run(synth.pre_ap_buses(moving=True), "--preap-window", "2")
    self.assertEqual(j["vehicle_profile"]["confidence"], "high")
    rc, j, _ = run(synth.pre_ap_buses(), "--preap-window", "2")   # speed 0 half the time: 2 s moving of 3.9 s
    self.assertEqual(j["vehicle_profile"]["evidence"]["seconds_moving"], 2.0)

  def test_tinkla_pre_ap_fixture(self):
    # Tinkla: comma sends 0x488/0x2B9/0x214 itself; carFingerprint and param say pre-AP; safety is upstream tesla
    rc, j, txt = run(synth.pre_ap_buses(), sendcan={0: spoof}, fingerprint="TESLA PREAP MODEL S",
                     params={"TinklaAPForceFingerprint": b"TESLA PREAP MODEL S", "DongleId": b"0000000000000000"})
    vp = j["vehicle_profile"]
    self.assertEqual(vp["profile"], "pre-ap")
    self.assertEqual(vp["confidence"], "high")
    self.assertIn("Tinkla carFingerprint TESLA PREAP MODEL S", vp["fork_preap_hints"])
    self.assertTrue(any("TinklaAPForceFingerprint" in h for h in vp["fork_preap_hints"]))
    self.assertNotIn("DongleId", json.dumps(j))
    self.assertIn("pre-AP hint from the fork settings", txt)

  def test_nap_pre_ap_fixture_safety_37_does_not_crash(self):
    # NotAutopilot: safety model teslaPreap (37) is unknown to the bundled schema; the base tool crashed on it
    rc, j, txt = run(synth.pre_ap_buses(), sendcan={0: spoof}, fingerprint="TESLA_MODEL_S_PREAP", safety_model=37,
                     params={"NAPForcePreAP": b"1", "NAPCarType": b"1"})
    self.assertEqual(rc, 0)
    vp = j["vehicle_profile"]
    self.assertEqual(vp["profile"], "pre-ap")
    self.assertEqual(vp["confidence"], "high")
    hints = vp["fork_preap_hints"]
    self.assertIn("NotAutopilot carFingerprint TESLA_MODEL_S_PREAP", hints)
    self.assertIn("NotAutopilot safety model teslaPreap (37)", hints)
    self.assertTrue(any("NAPForcePreAP" in h for h in hints) and any("NAPCarType" in h for h in hints))
    self.assertEqual(j["carParams"]["safetyConfigs"][0]["safetyModel"], "teslaPreap")
    self.assertIn("teslaPreap:0", j["panda"]["safetyModes_seen"])

  def test_device_sent_spoof_never_counts_as_ap1(self):
    # 0x488/0x2B9/0x214 as panda transmit echoes (src 128 + bus) AND in sendcan: still pre-AP
    b = synth.pre_ap_buses()
    b[128] = spoof
    b[130] = spoof
    rc, j, _ = run(b, sendcan={0: spoof, 2: spoof})
    vp = j["vehicle_profile"]
    self.assertEqual(vp["profile"], "pre-ap")
    self.assertEqual(vp["evidence"]["ap1_0x488_buses"], [])
    self.assertEqual(vp["evidence"]["das_messages_received"], [])

  def test_ibooster_retrofit_on_pre_ap(self):
    rc, j, _ = run(synth.pre_ap_buses())
    ib = [d for d in j["retrofit_hardware"]["detected"] if d["id"] == "ibooster"]
    self.assertEqual({tuple(d["addresses"]) for d in ib}, {("0x554",), ("0x39d",)})
    rc, j, _ = run(synth.pre_ap_buses(), sendcan={0: lambda i: [(0x555, bytes(6))]})   # IVS_Command from the comma
    self.assertTrue(any(d["id"] == "ibooster" and d.get("sent_by_comma") for d in j["retrofit_hardware"]["detected"]))

  def test_radar_hints(self):
    b = synth.pre_ap_buses()
    radar = b[1]
    b[1] = lambda i: radar(i) + [(0x631, bytes(8))]
    rc, j, txt = run(b)
    hw = j["retrofit_hardware"]
    self.assertEqual(hw["radar_state"], {"1": {"active_0x300": False, "init_0x631": True}})
    self.assertTrue(any("radar not syncing (check VIN learn / GTW emulation)" in h for h in hw["hints"]))
    self.assertIn("radar not syncing", txt)
    b[1] = lambda i: radar(i) + [(0x631, bytes(8)), (0x300, bytes(8))]
    rc, j, _ = run(b)
    self.assertEqual(j["retrofit_hardware"]["radar_state"]["1"]["active_0x300"], True)
    self.assertNotIn("hints", j["retrofit_hardware"])
    self.assertNotIn("1", j["retrofit_hardware"]["unrecognized_addresses"])

  def test_stock_comma_pedal_ids_clash(self):
    b = synth.pre_ap_buses(pedal=False)
    b[2] = lambda i: [(0x201, bytes(6))]
    rc, j, _ = run(b, sendcan={2: lambda i: [(0x200, bytes(6))]})
    hw = j["retrofit_hardware"]
    self.assertTrue(any("clashes with SDM1 0x201" in d["label"] and d["bus"] == 2 for d in hw["detected"]))
    self.assertTrue(any(d["id"] == "pedal" and d.get("sent_by_comma") and d["addresses"] == ["0x200"] for d in hw["detected"]))
    self.assertTrue(any("0x551/0x552" in h for h in hw["hints"]))

  def test_vin_on_0x405_never_leaks(self):
    zero_vin = "0" * 17
    p16 = bytes([16, 0, 0, 0, 0]) + b"000"
    p17 = bytes([17]) + b"0000000"
    p18 = bytes([18]) + b"0000000"
    self.assertEqual(bf.vin_from_mux_pages(p16, p17, p18), zero_vin)
    self.assertIsNone(bf.vin_from_mux_pages(p16, p17, None))
    b = synth.pre_ap_buses()
    chassis = b[0]
    b[0] = lambda i: chassis(i) + [(0x405, (p16, p17, p18)[i % 3]), (0x2A9, bytes(8))]
    rc, j, txt = run(b, "--include-can-stats")
    s = json.dumps(j)
    self.assertNotIn(zero_vin, s)
    self.assertNotIn(zero_vin, txt)
    self.assertNotIn("0x405", json.dumps(j["can_stats"]))
    self.assertNotIn("0x2a9", json.dumps(j["can_stats"]))
    self.assertTrue(any(w.startswith("0x405:") for w in j["can_stats_withheld"]))
    self.assertTrue(any(w.startswith("0x2a9:") for w in j["can_stats_withheld"]))

  def test_enum_str_fallback(self):
    e = synth.LOG.Event.new_message(logMonoTime=1)
    ps = e.init("pandaStates", 1)[0]
    ps.safetyModel = 37
    self.assertEqual(bf.enum_str(ps.safetyModel, bf.SAFETY_MODEL_EXTRA), "teslaPreap")
    ps.safetyModel = 99
    self.assertEqual(bf.enum_str(ps.safetyModel, bf.SAFETY_MODEL_EXTRA), "unknown(99)")
    ps.safetyModel = "tesla"
    self.assertEqual(bf.enum_str(ps.safetyModel, bf.SAFETY_MODEL_EXTRA), "tesla")


class FactoryFingerprintTests(unittest.TestCase):
  """The published Tinkla/NotAutopilot fingerprints (address: length, zero payloads)."""
  def test_tinkla_nap_pre_ap_fingerprint_dict(self):
    fp = factory_fingerprints.PREAP
    rc, j, _ = run({0: lambda i: [(a, bytes(n)) for a, n in fp.items()]}, "--include-can-stats")
    vp = j["vehicle_profile"]
    self.assertEqual(vp["profile"], "pre-ap")
    self.assertEqual(vp["bus_roles"]["2"], "other")
    self.assertEqual(vp["evidence"]["gtw_dasHw"], [0])
    self.assertNotIn("0x405", json.dumps(j["can_stats"]))

  def test_tinkla_ap1_fingerprint_dict(self):
    fp = factory_fingerprints.AP1
    rc, j, _ = run({0: lambda i: [(a, bytes(n)) for a, n in fp.items()]})
    vp, hw = j["vehicle_profile"], j["retrofit_hardware"]
    self.assertEqual(vp["profile"], "ap1")
    self.assertIn("--car-profile ap2", vp["reason"])
    self.assertNotIn("ibooster", {d["id"] for d in hw["detected"]})
    self.assertEqual(hw["factory_hardware"][0]["addresses"], ["0x39d"])


class UnknownProfileTests(unittest.TestCase):
  def test_0x488_only_is_unknown(self):
    b = synth.pre_ap_buses()
    b[2] = lambda i: [(0x488, bytes(4))]
    rc, j, txt = run(b)
    vp = j["vehicle_profile"]
    self.assertEqual(vp["profile"], "unknown")
    self.assertIn("both 0x488 and 0x2B9", vp["reason"])
    self.assertIn("--car-profile", txt)
    self.assertIn("coverage", j)                                # AP1 semantics for the checklist

  def test_no_tesla_chassis_bus_is_unknown(self):
    b = {1: synth.pre_ap_buses()[1], 0: lambda i: [(0x4F7, bytes(3))]}
    rc, j, _ = run(b)
    self.assertEqual(j["vehicle_profile"]["profile"], "unknown")
    self.assertIn("no Tesla chassis bus", j["vehicle_profile"]["reason"])

  def test_gtw_dashw_without_das_is_unknown(self):
    b = synth.pre_ap_buses()
    chassis = b[0]
    b[0] = lambda i: chassis(i) + [(0x398, bytes([0x40]) + bytes(7))]     # GTW_carConfig GTW_dasHw = 1
    rc, j, _ = run(b)
    vp = j["vehicle_profile"]
    self.assertEqual(vp["profile"], "unknown")
    self.assertEqual(vp["evidence"]["gtw_dasHw"], [1])
    self.assertNotIn("0x398", json.dumps(j.get("can_stats", {})))

  def test_unknown_with_fork_hint_suggests_pre_ap(self):
    b = synth.pre_ap_buses()
    b[2] = lambda i: [(0x488, bytes(4))]
    rc, j, _ = run(b, fingerprint="TESLA_MODEL_S_PREAP")
    self.assertEqual(j["vehicle_profile"]["profile"], "unknown")    # hints never flip the decision
    self.assertIn("--car-profile pre-ap", j["vehicle_profile"]["reason"])

  def test_manual_profile_wins(self):
    rc, j, _ = run(ap1_buses(), "--car-profile", "pre-ap")
    self.assertEqual(j["vehicle_profile"]["profile"], "pre-ap")
    rc, j, _ = run(synth.pre_ap_buses(), "--car-profile", "ap2")
    self.assertEqual(j["vehicle_profile"]["profile"], "ap2")
    das = [c for c in j["coverage"]["checklist"] if c["signal"].startswith("DAS_control.")]
    self.assertTrue(das[0]["na"] and "AP2" in das[0]["na_reason"])


class Ap1RegressionTests(unittest.TestCase):
  def test_ap1_with_factory_ibooster(self):
    rc, j, txt = run(ap1_buses())
    vp, hw = j["vehicle_profile"], j["retrofit_hardware"]
    self.assertEqual(vp["profile"], "ap1")
    self.assertEqual(vp["evidence"]["ap1_0x488_buses"], [2])
    self.assertEqual(vp["evidence"]["ap1_0x2b9_buses"], [2])
    self.assertNotIn("ibooster", {d["id"] for d in hw["detected"]})
    self.assertEqual(hw["factory_hardware"][0]["addresses"], ["0x32d", "0x35d", "0x39d"])
    self.assertIn("0x227 len 5 (ap1 fingerprint)", vp["evidence"]["fingerprint_hints"])
    self.assertEqual(vp["bus_roles"], {"0": "chassis", "1": "radar", "2": "chassis", "4": "powertrain", "6": "powertrain"})
    self.assertTrue(j["coverage"]["core_sufficient_for_basic_port"], j["coverage"]["core_missing"])
    self.assertIn("Factory hardware seen", txt)

  def test_ap1_output_identical_to_base_apart_from_new_sections(self):
    try:
      src = subprocess.run(["git", "-C", str(synth.ROOT), "show", f"{BASE_COMMIT}:bogpilot_fingerprint.py"],
                           check=True, capture_output=True).stdout
    except Exception:
      self.skipTest("base commit not available")
    d = tempfile.mkdtemp()
    path = os.path.join(d, "base_fingerprint.py")
    with open(path, "wb") as f:
      f.write(src)
    spec = importlib.util.spec_from_file_location("base_fingerprint", path)
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)

    # the only intended change to existing AP1 output: three more addresses are withheld from --include-can-stats
    # (0x32D IBST_info ids/CRCs, 0x405 VIN, 0x2A9 car config); the fixture sends 0x32D
    newly_withheld = {"0x32d", "0x405", "0x2a9"}

    def strip(j):
      for k in ("vehicle_profile", "retrofit_hardware", "tool_version"):
        j.pop(k, None)
      if "coverage" in j:
        j["coverage"].pop("profile", None)
      for buses in j.get("can_stats", {}).values():
        for addrs in buses.values():
          for a in newly_withheld:
            addrs.pop(a, None)
      if "can_stats_withheld" in j:
        j["can_stats_withheld"] = [w for w in j["can_stats_withheld"] if w.split(":")[0] not in newly_withheld]
      return j
    explicit_map = ("--bus-map", "0=chassis,1=radar,2=chassis,4=powertrain,6=powertrain")   # = the base layout
    for extra, new_only in (((), ()), (("--include-can-stats",), ()), (("--no-coverage",), ()),
                            (("--include-can-stats",), explicit_map + ("--car-profile", "ap1"))):
      _, new, _ = run(ap1_buses(), *extra, *new_only)
      _, old, _ = run(ap1_buses(), *extra, mod=base)
      if "--include-can-stats" in extra:
        self.assertIn("0x32d", json.dumps(old["can_stats"]))
        self.assertNotIn("0x32d", json.dumps(new["can_stats"]))
      self.assertEqual(json.dumps(strip(new), sort_keys=True), json.dumps(strip(old), sort_keys=True), extra)

  def test_ap1_still_requires_das(self):
    rc, j, _ = run(ap1_buses())
    self.assertEqual(j["vehicle_profile"]["profile"], "ap1")
    self.assertTrue(j["coverage"]["core_sufficient_for_basic_port"])
    b = synth.pre_ap_buses()
    rc, j, _ = run(b, "--car-profile", "ap1")
    self.assertIn("Stock DAS control (bus 2)", j["coverage"]["core_missing"])

  def test_radar_bus_vin_address_is_not_taken_as_das(self):
    # 0x2B9 on the radar bus is the VIN sent to the radar (same address as DAS_control): must not mean AP1
    b = synth.pre_ap_buses()
    radar = b[1]
    b[1] = lambda i: radar(i) + [(0x2B9, bytes(8))]
    rc, j, _ = run(b)
    self.assertEqual(j["vehicle_profile"]["profile"], "pre-ap")

  def test_non_tesla_unrecognised_car_has_no_coverage(self):
    rc, j, _ = run({0: lambda i: [(0x123, bytes(8)), (0x456, bytes(4))]}, car_name="mock")
    self.assertNotIn("coverage", j)


if __name__ == "__main__":
  unittest.main()
