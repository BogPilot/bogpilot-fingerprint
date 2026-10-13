# bogpilot-fingerprint

This tool turns your own openpilot/BogPilot drive logs (`rlog` files) into a small **privacy-safe
fingerprint file** for porting BogPilot to legacy Tesla Model S / Model X with **Autopilot 1
(AP1, pre-AP2)**.

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

The tool prints a summary: car model detected, firmware, CAN message counts per bus, the coverage
report (CORE first, then OPTIONAL, then FUTURE), blind-spot (0x399) status, and the privacy self-check result.
**Open the JSON in a text editor and look at it before you share it.** It is plain text.

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
* the **VIN** everywhere: `carParams.carVin`, firmware strings, and the VIN that the car itself sends on CAN.
  The tool rebuilds that VIN internally only to make sure it is not in the output.
* camera, driver monitoring, microphone, video files
* all timestamps (`logMonoTime`, wall clock, route/segment names, the car's clock on CAN)
* device and user IDs: dongle ID, device serial, boot log ID, IMEI/ICCID, Wi-Fi/network info, IP addresses
* `params`, log/error messages, process lists, device state
* raw CAN frames (payloads are never exported)

**Messages never included in `--include-can-stats`** (even their changing bits):

| address | why |
|---|---|
| 0x508 | VIN (3 pages of ASCII) |
| 0x2B9 | VIN sent to the radar (same address is DAS_control on the AP bus; it is hidden on all buses to be safe) |
| 0x5D8, 0x562, 0x209 | odometer values |
| 0x3D2 | lifetime energy counters |
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
(e.g. "AP1 fingerprint: Model S 2015 P85D"), mention the model/year (no VIN), and **attach**
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
