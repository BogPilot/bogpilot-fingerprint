# bogpilot-fingerprint

This tool turns your own openpilot/BogPilot drive logs (`rlog` files) into a small **privacy-safe
fingerprint file** for porting BogPilot to legacy Tesla Model S / Model X with **Autopilot 1
(AP1, pre-AP2)**, and to **pre-AP Model S (2012–2014, no factory Autopilot hardware)**, including cars
retrofitted with custom hardware such as a Tesla Bosch radar, a comma pedal or an iBooster
(see [Pre-AP cars and custom hardware](#pre-ap-cars-and-custom-hardware)).

* It runs **on your own computer**. It **never uploads anything**; you decide whether to share the result.
* It keeps only what a developer needs to recognise your car: which CAN messages exist, how long they are,
  roughly how often they are sent, firmware part numbers, and car parameters.
* It removes your **VIN, location/GPS, camera, driver-monitoring, microphone, timestamps, device IDs** and more
  (full list below). Before it writes the file, it checks the output again and refuses to save if anything
  looks personal.
* It also tells you whether your recording covered everything needed (the *coverage report*), so you know
  whether to record again.

You do **not** need an openpilot checkout. The log format (cereal schema) and the Tesla DBC files are bundled.

---

## 1. Install (once)

You need Python 3.8 or newer and two packages:

```bash
python3 -m pip install --user pycapnp zstandard
```

Or, in a separate environment:

```bash
python3 -m venv fp-venv
. fp-venv/bin/activate            # Windows: fp-venv\Scripts\activate
pip install pycapnp zstandard
```

## 2. Record a drive

Follow the [Recording checklist](#5-recording-checklist) below. One drive of 10–20 minutes that covers
the CORE list is enough.

## 3. Copy the rlogs to your computer

Logs live on the device under `/data/media/0/realdata/`. Each folder there is one ~1-minute segment named
`<route>--<number>` (for example `0000002a--5e8e1c6d72--0`, `...--1`, ...). Use the **rlog** files.
`qlog` files are ignored because they do not have every CAN message.

**Over SSH** (device and computer on the same Wi-Fi; enable SSH and add your GitHub SSH key in the device
settings first). Use `-i` to point at the private key that matches the key you added:

```bash
# find the device IP in Settings -> Network, then list routes (newest last)
ssh -i ~/.ssh/id_ed25519 comma@<device-ip> 'ls -tr /data/media/0/realdata/ | tail -n 30'

# copy every segment of one route into a folder on your computer
mkdir -p my_drive
scp -i ~/.ssh/id_ed25519 -r 'comma@<device-ip>:/data/media/0/realdata/<route>--*' my_drive/
```

(`<route>` is the part before the last `--number`. Copying the whole segment folders is fine; the tool
only reads the `rlog*` files and ignores video files. To save time, copy only `.../<route>--*/rlog*` instead.)

**Via comma connect** (if your device is paired): open the drive, choose to upload/download the
"rlogs", and save them into one folder.

## 4. Run it

```bash
python3 bogpilot_fingerprint.py my_drive/ -o my_car_fingerprint.json
```

You can also pass individual files: `rlog`, `rlog.zst` or `rlog.bz2`.

| option | what it does |
|---|---|
| `-o FILE` | output file (default `my_car_fingerprint.json`) |
| `--zip` | also write a `.zip` with the JSON inside (easier to attach to an issue) |
| `--include-can-stats` | adds, per CAN message, *which bits ever changed* and per-byte min/max. Still no raw frames or timestamps. Helps developers a lot; see the privacy notes below. |
| `--force` | write the file even if the privacy self-check complained. **Read the warning first.** |
| `--no-coverage` | skip the recording-coverage report |
| `--car-profile auto\|ap1\|ap2\|pre-ap` | which car type / checklist to use. `auto` (default): `ap1` when both factory AP1 messages 0x488 and 0x2B9 are received, `pre-ap` when a Tesla chassis bus shows no factory Autopilot messages, otherwise `unknown` (then choose one). `ap2` is manual only. See [Pre-AP cars](#pre-ap-cars-and-custom-hardware). |
| `--preap-window SECONDS` | seconds of driving without factory Autopilot messages for a *high confidence* pre-AP result (default 60; shorter logs are judged on the whole log) |
| `--hw radar,pedal,...` | the retrofit hardware you added, from `radar`, `pedal`, `ibooster`, `epas-firmware`, `harness`, `other`. It is written to the file and checked against the log. |
| `--bus-map 0=chassis,1=radar,...` | which panda bus carries what, if your wiring differs from the default: BogPilot's AP1 layout (`0=chassis,1=radar,2=chassis,4=powertrain,6=powertrain`), or `0=chassis,1=radar,2=other` for a pre-AP car. Roles: `chassis`, `powertrain`, `radar`, `other`. |

The tool prints a summary: car model detected, firmware, CAN message counts per bus, the coverage
report (CORE first, then OPTIONAL, then FUTURE), blind-spot (0x399) status, and the privacy self-check result.
**Open the JSON in a text editor and look at it before you share it.** It is plain text.

### Pre-AP cars and custom hardware

A 2012–2014 Model S without Autopilot hardware has no Autopilot ECU (DAS), no camera and no radar
from the factory. The tool handles that:

* **Detection (car type).** `--car-profile` always wins. With `auto` (the default):
  * **ap1** only when **both** factory AP1 messages, 0x488 DAS_steeringControl and 0x2B9 DAS_control, are
    *received from the car* on bus 0 or 2 (or a bus you mapped as `chassis`). A bus mapped or detected as
    radar never counts. Other DAS messages are listed as supporting evidence only.
  * **pre-ap** when a Tesla chassis bus is present and **no** factory Autopilot message is received. The
    tool reports how many seconds the car was moving (from ESP_vehicleSpeed). With at least 60 s of driving
    (`--preap-window`) the result is *high* confidence. A shorter log is judged on the whole log and marked
    *low* confidence, unless the log also has a NotAutopilot/Tinkla pre-AP setting (see below).
  * **unknown** in every other case (for example only 0x488, a few DAS messages, no Tesla chassis bus, or
    GTW_carConfig saying DAS hardware is fitted while no DAS message is seen). The report gives the reason.
    Re-run with `--car-profile ap1`, `ap2` or `pre-ap`.
  * **ap2** is never chosen automatically. AP2 cars send 0x488/0x2B9 too, so an AP2 car shows up as `ap1`:
    use `--car-profile ap2`. AP2 messages are not modelled yet (real AP2 logs are needed), so the DAS
    checklist items are `n/a` for `ap2`.
* **Frames the comma sends never count.** NotAutopilot and Tinkla send 0x488, 0x2B9 and 0x214 from the comma
  on a pre-AP car. Those frames are in `sendcan` and in the panda's transmit echoes, which the tool ignores for
  detection, so they cannot make a pre-AP car look like AP1.
* **Fork settings are hints only.** The report lists these when it finds them, and they raise the confidence
  of a pre-AP result, but they never change the car type on their own:
  NotAutopilot safety model `teslaPreap` (37), `carFingerprint` `TESLA_MODEL_S_PREAP`, params
  `NAPForcePreAP=1` (on by default in NotAutopilot) and `NAPCarType=1`; Tinkla `carFingerprint`
  `TESLA PREAP MODEL S` and param `TinklaAPForceFingerprint`. (Tinkla uses its own panda firmware with the
  upstream `tesla` safety model, so its safety model is not a hint.) Factory fingerprint lengths are shown as
  hints too: 0x505 (8 bytes) and 0x227 with 4 bytes point to pre-AP, 0x227 with 5 bytes to AP1.
* **Bus map.** For a pre-AP car, without `--bus-map`, the tool uses `0=chassis,1=radar,2=other`: chassis on
  CAN0, Bosch radar on CAN1 and the pedal on CAN2, as Tinkla and NotAutopilot wire it (the pedal can also be
  on CAN0). AP1 keeps `0=chassis,1=radar,2=chassis,4=powertrain,6=powertrain`.
* **Checklist.** Items that only the factory Autopilot ECU sends (stock DAS control, blind spot 0x399,
  stock cluster messages, DAS_steeringControl 0x488, stock AP wiper/high-beam requests) are shown as
  `n/a` with the reason, and do not count against the VERDICT. EPB_epasControl (0x214) is also `n/a`: a
  pre-AP car does not send it (Tinkla/NotAutopilot send it from the comma). All other CORE items are still
  required.
* **Not recognised by openpilot yet?** If openpilot did not identify the car (`carName` is `mock`) but
  the log has a Tesla chassis bus, the coverage report is still made, with a note.
* **Retrofit hardware** is reported separately and never decides the car type (address and length only):
  * Tesla Bosch radar: 0x301, 0x302, 0x501 plus radar track messages, on any bus. The radar CORE check uses
    whichever bus it is on. On the radar bus, 0x300 means the radar is active and 0x631 means it is
    initialising. 0x631 without 0x300 gives the hint "radar not syncing (check VIN learn / GTW emulation)".
    A Bosch radar in a pre-AP car only works after it has learned the car's VIN and while the panda
    emulates the gateway messages it expects (both Tinkla and NotAutopilot do this).
  * comma pedal: 0x552 from the pedal, 0x551 sent by the comma. 0x200/0x201 with 6 bytes on a non-chassis
    bus means a pedal with the **stock comma firmware IDs**, which clash with SDM1 (0x201, seat belt);
    flash the Tinkla/NotAutopilot pedal firmware (0x551/0x552).
  * iBooster: the retrofit iBooster ECU (0x554, 0x556; 0x553 and 0x555 sent by the comma). The IBST_*
    messages (0x39D, 0x32D, 0x35D) are **factory on AP1 cars**, so they count as a retrofit only on a pre-AP
    car; on AP1 they are listed under `retrofit_hardware.factory_hardware`.
  * EPAS firmware cannot be read from the log, and a patched pre-AP EPAS often runs AP1 firmware anyway, so
    the EPAS firmware never helps tell pre-AP from AP1. `--hw epas-firmware` is recorded as you declare it.

  Declare what you installed with `--hw`; anything you declared but the log does not show is flagged.
* **Unknown messages.** Extra messages from aftermarket hardware never break the tool. They are kept in
  the CAN fingerprint, and addresses that the bundled Tesla DBCs do not describe are listed per bus under
  `retrofit_hardware.unrecognized_addresses`.
* **Wiring.** If your harness puts the chassis, powertrain or radar on different panda buses, the summary
  shows the layout the log suggests. Re-run with `--bus-map` to match it.

Example for a pre-AP car with a Bosch radar and a pedal:

```bash
python3 bogpilot_fingerprint.py my_drive/ -o my_car_fingerprint.json --car-profile pre-ap --hw radar,pedal
```

This tool only records and checks your logs. It does not make BogPilot drive a pre-AP car. That still
needs a pre-AP car port in BogPilot (and, for steering, an EPAS that accepts steering commands).

### Coming from NotAutopilot

If your pre-AP car already runs NotAutopilot (or Tinkla), record your drive with it as usual and then:

1. **Choose the profile yourself:** `--car-profile pre-ap`. Auto-detection usually gets there too (and the
   report lists the NotAutopilot settings it found), but naming the profile removes any doubt.
2. **Bus map:** the pre-AP default `0=chassis,1=radar,2=other` matches NotAutopilot's wiring (pedal on CAN2).
   If you moved the pedal to CAN0 or wired anything else differently, pass `--bus-map`.
3. **EPAS:** if you already flashed the patched EPAS firmware with NotAutopilot or Tinkla, there is nothing
   to redo for this tool. Add `--hw epas-firmware` so the report says so; the log cannot show it.
4. **Radar:** if you use a Bosch radar, it must have learned your VIN and the panda must emulate the gateway
   (NotAutopilot does both when the radar is enabled). If the report says "radar not syncing", fix that in
   NotAutopilot first, then record again.
5. **NotAutopilot logs:** older versions of this tool stopped on NotAutopilot logs (safety model
   `teslaPreap`, 37, is newer than the bundled log schema). This version reads them.

A matching BogPilot setting (to pick the pre-AP car type on the device, like `NAPCarType`) is **planned,
not shipped**. Until it exists, `--car-profile` here is only for this report.

---

## 5. Recording checklist

> **Safety first.** Do the parked steps with the car in **Park** and your foot on the brake where needed.
> Do the driving steps **only when it is safe and legal**, on roads you know, with full attention.
> **Never engage software features you are not familiar with** just to complete this list. A missing
> OPTIONAL item is fine. If you skip a step, the coverage report will simply say so.

How to do each action: **hold it 3–5 seconds, then release and wait 3–5 seconds before the next one.**
The pauses let the tool tell actions apart. Make sure openpilot/BogPilot is **not engaged** during
the parked steps.

### CORE: needed for a basic port (steering, cruise, safety alerts)

Parked (ignition on, car in P):

| # | action | timing | enables in BogPilot |
|---|---|---|---|
| 1 | Turn the car on, stay in **P**, do nothing | 30 s idle | CAN fingerprint, firmware (carFw), EPAS/EPB status, stock DAS messages |
| 2 | Unbuckle the driver seat belt, then buckle again | 3–5 s each | seat-belt alert |
| 3 | Open and close **each door one at a time**: front left, front right, rear left, rear right | 3–5 s open, 3–5 s pause | door-open alert |
| 4 | Open and close the **frunk**, then the **trunk/liftgate** | 3–5 s open | door-open alert (BogPilot counts the frunk and trunk as doors) |
| 5 | Turn-signal lever: **left**, release; **right**, release | 3–5 s each | blinkers, lane-change blinker events |
| 6 | Press the brake pedal firmly, release; repeat once | 3–5 s each | disengage on brake |
| 7 | Brake held, shift **R → N → D → P** (N is optional) | 3–5 s in each | gear (engage only in D, reverse) |
| 8 | Back in P, with the system **disengaged**, cruise stalk: **pull toward you**; **up short**; **down short**; **up full**; **down full**; **push away (cancel)** | 3–5 s each, pause between | cruise-stalk buttons (set/resume/cancel, speed up/down) |
| 9 | Turn the steering wheel **slowly** to full lock left, back to centre, full lock right, back to centre | ~10 s each way | steering angle, steering rate |
| 10 | Hold the wheel centred and push gently against it left, then right (as if overriding) | 3–5 s each | driver torque, hands-on level (override detection) |

Short drive:

| # | action | enables in BogPilot |
|---|---|---|
| 11 | Pull away gently; hold a steady **~25 mph (40 km/h)** for 20–30 s, then **~45 mph (70 km/h)** for 20–30 s | vehicle speed, accelerator |
| 12 | A few gentle accelerations and gentle braking | accelerator, brake |
| 13 | A few normal turns, plus lane changes **with the turn signal** on each side | steering, blinkers |
| 14 | Come to a **full stop and hold it for 5–10 s** (traffic light/stop sign) | standstill / stop-and-go |
| 15 | Reverse a short distance somewhere safe (parking lot) | reverse gear |
| 16 | If your car has TACC/cruise and you know how to use it: engage the **stock** cruise, change the set speed once with the stalk, then cancel it | cruise state, set speed, speed units |

### OPTIONAL: extra BogPilot features beyond a basic port

| # | action | enables in BogPilot |
|---|---|---|
| 17 | **Blind spot, left:** while driving, let a car pass you in the lane to your **left** (or drive slowly past a parked car on your left, e.g. in a parking lot). | blind-spot warnings from the stock DAS message **0x399** (lane-change safety) |
| 18 | **Blind spot, right:** the same on your **right** side. | blind-spot (0x399) |
| 19 | Twist the end of the cruise stalk (follow distance) one step each way, if your car has it | stalk follow-distance setting |
| 20 | Drive past a few speed-limit signs / roads with known limits | dashboard speed limit (fused / map / MPP speed limit) |
| 21 | (No action needed) Normal driving with the stock AP1 system powered | stock cluster messages and stock steering message, used for AP1 cluster display |

### FUTURE: planned BogPilot features (nice to capture now, not required)

BogPilot does not read these signals yet. Capturing them now means nobody has to record again later.

| # | action | for planned BogPilot feature |
|---|---|---|
| 22 | **Wipers:** if it is raining, use the wiper stalk normally (intermittent and continuous). If it is dry, wet the glass first with the washer, then step the stalk through each position and back to off (3–5 s each). Do not run wipers on dry glass. Turning auto-wipers on/off in the car settings also helps. | rain-aware following distance / curve speed |
| 23 | **High beams:** at night, on an empty road where high beams are legal, switch them on for 5–10 s, then off. Do not dazzle other drivers. If you do not drive at night, flash them 2–3 times while parked facing a wall. | night mode: SLC speed offset rolled back (~2 mph in lower speed bands, ~3 mph in higher bands) |

FUTURE items never affect the VERDICT.

CORE and OPTIONAL list only signals that BogPilot's AP1 code actually reads. Hazards and parking sensors are not
used, so they are not on the list. The frunk and trunk *are* listed because BogPilot treats them as doors for
the door-open alert.

### Reading the coverage report

For every item the report prints one of:

* `ok`: seen, with all needed values (e.g. every gear, every stalk move)
* `partial`: seen, but some needed values never appeared (they are listed, so you know what to redo)
* `no change`: the message exists but never changed (e.g. you never turned the wheel)
* `never 0`: speed never reached zero (no full stop)
* `MISSING`: the message was not in the log at all

The report lists CORE first, then OPTIONAL, then FUTURE. It then prints a **VERDICT**: whether the log is
**sufficient for a basic port** (all CORE items OK). OPTIONAL and FUTURE items do not affect it.
If not, it lists what is missing. Record another short drive that does just those steps and run the tool
on **both** route folders together (`python3 bogpilot_fingerprint.py drive1/ drive2/ -o ...`).

The blind-spot section shows whether message **0x399** exists (bus, length, rate) and whether the left or
right warning was ever active.

---

## 6. What is kept and what is removed

**Kept**

* **CAN fingerprint** for each bus: message address → length, plus a rounded send rate (e.g. 10/50/100 Hz),
  for received (`can`) and sent (`sendcan`) traffic. No message contents.
  Also given in openpilot `FINGERPRINTS` style.
* **Firmware versions** (`carFw`): ECU, address and version string. VIN-like text, long serial-like numbers
  and known IDs are replaced by `<redacted>`.
* **Car parameters** (`carParams`): model, safety model, mass/wheelbase/steer ratio, capabilities, and
  so on. **`carVin` is removed.**
* **Software**: openpilot version, and the git branch and commit only for well-known public forks
  (commaai, BogPilot, FrogPilot, sunnypilot, dragonpilot, ...). For a personal fork, the user name
  is replaced (`github.com/<personal fork>/openpilot`) and the branch/commit are hidden. Device type and OS version.
* **Panda**: hardware type and firmware version only.
* **Coverage report**: which checklist signals were seen and which values appeared (e.g. `DI_GEAR_D`).
  No times, no positions. (If you used high beams or wipers, the file shows that they were used. It does not show
  when or where.)
* With `--include-can-stats` only: per message, which bits ever changed, and per-byte min/max.

**Removed / never read**

* GPS and location: `gpsLocation*`, `ubloxGnss`, `qcomGnss`, `liveLocation*`, navigation, mapd, and the
  car's own GPS CAN messages (see the table below)
* the **VIN** everywhere: `carParams.carVin`, firmware strings, and the VIN that the car itself sends on CAN
  (0x508, 0x405, and the copy sent to the radar on 0x2B9).
  The tool rebuilds that VIN internally only to make sure it is not in the output.
* camera, driver monitoring, microphone, video files
* all timestamps (`logMonoTime`, wall clock, route/segment names, the car's clock on CAN)
* device and user IDs: dongle ID, device serial, boot log ID, IMEI/ICCID, Wi-Fi/network info, IP addresses
* `params` (only three fork settings, `NAPForcePreAP`, `NAPCarType` and `TinklaAPForceFingerprint`, are compared
  with fixed values to spot a pre-AP setup; no param value is written), log/error messages, process lists, device state
* raw CAN frames (payloads are never exported)

**Messages never included in `--include-can-stats`** (even their changing bits):

| address | why |
|---|---|
| 0x508 | VIN (3 pages of ASCII) |
| 0x2B9 | VIN sent to the radar (same address is DAS_control on the AP bus; it is hidden on all buses to be safe) |
| 0x405 | VIN (pre-AP cars send it on the chassis bus instead of 0x508) |
| 0x2A9 | car configuration / country code sent to the radar |
| 0x5D8, 0x562, 0x209 | odometer values |
| 0x3D2 | lifetime energy counters |
| 0x32D | iBooster part/CRC identifiers |
| 0x3D8, 0x068, 0x2F8 | GPS position / elevation / heading |
| 0x246 | sun position (reveals time and place) |
| 0x3C8, 0x398 | map data / country code |
| 0x318 | car clock (date/time) |
| 0x600–0x7FF | diagnostic (UDS) traffic, which can carry VIN and serial numbers |

Any message whose contents look like VIN text is also withheld automatically. Blind spot **0x399** is
*not* withheld; its stats are included.

**Privacy self-check.** Before writing, the finished file is scanned for: VIN-like strings (and pieces of
your actual VIN), coordinate pairs, e-mail addresses, IP and MAC addresses, the words
dongle/serial/IMEI/ICCID, home-directory paths and long numbers. If anything is found, nothing is
written and the tool shows what it found (exit code 2). Only use `--force` if you have looked and you
are sure it is harmless (for example, a part number that only looks like a serial).

---

## 7. Sharing it

The tool does not upload. To help the BogPilot port, open an issue on the BogPilot GitHub repository
(e.g. "AP1 fingerprint: Model S 2015 P85D" or "Pre-AP fingerprint: Model S 2013 P85 + Bosch radar"),
mention the model/year and any retrofit hardware (no VIN), and **attach**
`my_car_fingerprint.json` (or the `.zip`). Attach the file rather than pasting it, and look through it first.

## 8. Troubleshooting

* `ModuleNotFoundError: capnp` / `zstandard`: run the install step again (inside your venv if you use one).
* `no rlog files found`: point the tool at the folder that contains the `<route>--N` segment folders,
  or at the `rlog*` files directly. `qlog` files are not used.
* A segment is corrupted or truncated (e.g. the car was switched off while writing): the tool reads
  what it can and continues.
* The coverage report says `MISSING` for many items while the car is a Tesla: make sure you copied **rlogs**
  from a drive where openpilot/BogPilot was running and the car was detected.

## License

MIT (see `LICENSE`). Bundled `schema/` and `dbc/` files are from comma.ai's openpilot/opendbc (MIT).
