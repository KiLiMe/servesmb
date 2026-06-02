# Time Machine over SMB

This server can act as a macOS **Time Machine** network backup target. macOS
stores each backup as a sparse-bundle disk image on the share; Time Machine
attaches and mounts that image over SMB and copies into it. Enabling this
requires marking the share with `type: "timemachine"`, which turns on the Apple
SMB extensions macOS needs to accept the destination.

Tested against macOS clients backing up over SMB 3.1.1 (AES-128-GCM).

---

## Requirements

- **SMB 3 must be enabled.** macOS negotiates SMB 3.1.1 for Time Machine.
- **Mark the share as Time Machine.** Set it either in the JSON config
  (`"type": "timemachine"`) or on the command line with
  `-share NAME:PATH:type=timemachine` (the `:type=` token may be combined with
  `:ro` in either order).
- **Use an authenticated user** for the backup share (not guest). Give that
  account write access to the share.
- **Back the share with a large volume.** The server advertises the *real* free
  space of the disk holding the share's directory, and Time Machine sizes its
  backup against that. Point the share at a disk with room for the backup
  (rule of thumb: 1.5–2× the data you are backing up).
- Open TCP **445** on the server's firewall.
- **Optional: advertise over Bonjour** with `-mdns`. The server then publishes
  `_smb._tcp`, `_device-info._tcp` (model `TimeCapsule6`) and `_adisk._tcp` (one
  `dkN=adVN=<share>,adVF=0x82` record per Time Machine share, plus
  `sys=waMa=0,adVF=0x100`), so the destination auto-appears in the macOS Time
  Machine disk list without typing the address. Open UDP **5353** for mDNS.

---

## 1. Configure the share (server side)

Create a config file, e.g. `timemachine-config.json`:

```json
{
  "listen_address": "0.0.0.0",
  "port": 445,
  "domain": "WORKGROUP",
  "server_name": "GOSMB",
  "enable_smb1": true,
  "enable_smb2": true,
  "enable_smb3": true,
  "users": {
    "backup": "backuppass"
  },
  "shares": [
    {
      "name": "TIMEMACHINE",
      "path": "D:\\TimeMachineBackups",
      "comment": "Apple Time Machine target",
      "readonly": false,
      "guest_access": false,
      "type": "timemachine"
    }
  ]
}
```

Notes:

- `path` is the directory that will hold the backup; it is created if missing.
  Absolute paths are supported (as above). Relative paths are resolved against
  `shares_path` if you set it.
- `type: "timemachine"` is the only field that distinguishes a Time Machine
  share from a normal one. Omit it (or use any other value) for regular shares.
- `users` values may be a plaintext password (as above) or an object
  `{ "nt_hash": "<32-hex>" }`.

Run the server:

```powershell
# Windows
.\smbserver.exe -config timemachine-config.json
```

```bash
# Build + run elsewhere
go build -o smbserver ./cmd/servesmb
./smbserver -config timemachine-config.json
```

When the config file sets the `enable_smb1/2/3` fields, they control which
protocol versions are enabled (overriding the `-smb` flag). If you don't use a
config file for versions, pass `-smb 1,2,3` to enable all three. Other useful
flags: `-netbios=false` to disable NetBIOS, `-debug 3` for protocol logging,
`-port 8445` to test on a non-privileged port.

---

## 2. Connect from macOS

### Option A — System Settings (GUI)

1. **System Settings → General → Time Machine → Add Backup Disk…**
2. The share appears as an available disk because it advertises the Time
   Machine capability. Select it.
3. Enter the share credentials (`backup` / `backuppass`) when prompted, choosing
   **Registered User** (not Guest).
4. Time Machine creates the backup disk image and starts the first backup.

### Option B — `tmutil` (command line)

```bash
# Set the destination (credentials inline)
sudo tmutil setdestination -a "smb://backup:backuppass@SERVER_IP/TIMEMACHINE"

# Confirm it registered
tmutil destinationinfo

# Start a backup now (force; plain `startbackup --auto` may be throttled/deferred)
sudo tmutil startbackup
```

---

## 3. Verify

```bash
# Backup phase + progress (FindingBackupVol → MountingDiskImage →
# PreparingSourceVolumes → Copying ...)
tmutil status

# Confirm the server advertises the Apple/Time Machine capabilities
smbutil statshares -a        # look for OS_X_SERVER / Time Machine support
```

A working run progresses to `BackupPhase = Copying` with `bytes` and `files`
increasing, and the server's share directory fills with
`<host>.sparsebundle/` (containing `Info.plist`, `token`, and `bands/`).

---

## How it works

Setting `type: "timemachine"` makes the server, for that share only:

- Answer the **AAPL** create context advertising the Apple SMB extensions,
  including the **full-sync volume capability** and a Time Machine model, so
  macOS recognizes the share as a backup target.
- Grant **durable handles (DH2Q) + leases (RqLs)** and report **maximal access
  (MxAc)**, which macOS requires to configure SMB reconnect for the destination.
- Implement **SMB2 FLUSH** correctly (Time Machine issues a flush after writes
  because full-sync is advertised).
- Report the **real free/total space** of the backing volume in the filesystem
  size responses, so Time Machine sizes its disk image correctly.

Apple metadata (Finder info, the `com.apple.quarantine` attribute, resource
forks) is stored in plain **AppleDouble** (`._`) sidecar files. The server does
**not** advertise SMB named streams for Time Machine shares — doing so caused
the disk-image attach to fail when macOS initialized its quarantine record.

Whole-Mac negotiation also relies on the server answering the legacy SMB1
multi-protocol negotiate with the wildcard dialect, so leaving SMB1 enabled
(`-smb 1,2,3`) helps macOS reach SMB 3.1.1; SMB2/3-only also works for clients
that negotiate SMB2 directly.

---

## Troubleshooting

**The share doesn't appear in Time Machine's disk list / "Failed to mount
destination" (error 32).**
- Confirm the share has `type: "timemachine"` and SMB3 is enabled.
- Remove any stale, non–Time Machine `*.sparsebundle` left in the share
  directory — Time Machine inspects existing bundles and bails if one lacks a
  valid `com.apple.TimeMachine.MachineID.plist`.

**Backup stays at `Running = 0` after `tmutil startbackup --auto`.**
- `--auto` respects power/network throttling and may defer. Use
  `sudo tmutil startbackup` (no `--auto`) to force one immediately.

**"Not enough space" or the image is smaller than expected.**
- The server reports the real free space of the disk holding the share's
  `path`. Move `path` to a larger volume, or free space on that disk.

**Authentication errors.**
- Use a real account (`guest_access: false` on the backup share). Connect as a
  **Registered User**; verify the username/password in the config.

**Backup is extremely slow or stalls for ~2 minutes at a time.**
- This was a server bug in how compound (multi-PDU) SMB2 responses were signed:
  the server signed the whole chain once and put the signature in only the first
  header, so on a signed connection macOS silently dropped every compound
  response and blocked the matching request until its ~120 s timeout (one stall
  per sparsebundle band file macOS opened). Fixed — each compound PDU is now
  signed individually. Make sure you are running a current build
  (`go build ./...`).
- A one-time ~2-3 minute pause while macOS *mounts* the freshly formatted backup
  volume (first backup) is normal and client-side, not a stall.

**Inspect the macOS side.**
```bash
# Time Machine / backupd reasoning
sudo log show --last 10m --predicate 'processImagePath CONTAINS "backupd"' --info --debug
```

> Reminder: a full first backup of a Mac can be tens to hundreds of GB. Make
> sure the backing volume is large enough before kicking it off.
