# SMB Server in Go

A fully functional, customizable SMB server implementation in Go that supports SMB versions 1, 2, and 3 with complete NetBIOS support, NTLMv2 authentication, and dynamic share configuration.

**Module:** `github.com/3xport/servesmb`

## Features

- **Multi-protocol support**: SMB1 (CIFS), SMB2 (2.0.2, 2.1), and SMB3 (3.0, 3.0.2, 3.1.1)
- **Library Support**: Reusable Go module with public API (`pkg/server`)
- **Modular Filesystems**: Support for OS, Memory, or custom filesystems via `spf13/afero`
- **NetBIOS support**: Full NetBIOS Name Service (UDP 137) and Session Service (TCP 139)
- **Dynamic Configuration**: Configure shares dynamically via CLI or JSON
- **Authentication**:
    - NTLMv2 support
    - NTLM Hash support (Pass-the-Hash compatible)
    - Guest access
- **macOS Compatibility**: Optimized for macOS clients (Finder, `mount_smbfs`)
- **Time Machine**: Use a share as a macOS Time Machine backup target via `"type": "timemachine"` — see [docs/timemachine.md](docs/timemachine.md)
- **File Operations**: Read, write, create, delete, directory listing
- **Security**:
    - Path traversal protection
    - Read-only share support
    - NTLM hash logging for auditing
- **Legacy Compatibility**: Works with older clients (Windows XP/2000) and modern clients (Windows 10/11, macOS, Linux)

## Quick Start

### Build

```bash
cd servesmb
go build -o servesmb ./cmd/servesmb
```

Or just run directly:

```bash
go run ./cmd/servesmb
```

### Run with Dynamic Shares (CLI)

Define shares directly on the command line using the `-share` flag.
Format: `-share NAME:PATH[:ro][:type=timemachine]` (the `:ro` and
`:type=timemachine` tokens are optional and may appear in either order).

```bash
# DATA (Read/Write), BACKUP (Read-Only), TM (macOS Time Machine target)
sudo ./smbserver -port 445 \
  -share DATA:./data \
  -share BACKUP:/mnt/backup:ro \
  -share TM:/mnt/timemachine:type=timemachine \
  -auth user:password
```

`type=timemachine` enables the Apple SMB extensions a macOS Time Machine
destination needs — the same as `"type": "timemachine"` in the JSON config
(see `docs/timemachine.md`).

### Run with Configuration File (JSON)

Create a `config.json` file for advanced setups (hashes, mixed auth):

```json
{
  "port": 445,
  "users": {
    "alice": "password123",
    "bob": { "nt_hash": "8846F7EAEE8FB117AD06BDD830B7586C" }
  },
  "shares": [
    {
      "name": "DOCUMENTS",
      "path": "/home/alice/docs",
      "readonly": false
    },
    {
      "name": "PUBLIC",
      "path": "/tmp/public",
      "guest_access": true
    },
    {
      "name": "TIMEMACHINE",
      "path": "/mnt/backups",
      "guest_access": false,
      "type": "timemachine"
    }
  ]
}
```

> The optional `"type": "timemachine"` field marks a share as a macOS Time
> Machine target (only settable via the config file, not `-share`). See
> [docs/timemachine.md](docs/timemachine.md).

Run the server:
```bash
sudo ./smbserver -config config.json
```

## Library Usage (Go Module)

The server is designed to be embedded in other Go applications.

```bash
go get github.com/3xport/servesmb
```

### Example: In-Memory SMB Server

```go
package main

import (
    "github.com/3xport/servesmb/pkg/protocol"
    "github.com/3xport/servesmb/pkg/server"
    "github.com/3xport/servesmb/pkg/shares"
    "github.com/spf13/afero"
)

func main() {
    // 1. Create ShareManager
    sm := shares.NewShareManager("")

    // 2. Create In-Memory Filesystem
    memFs := afero.NewMemMapFs()
    afero.WriteFile(memFs, "readme.txt", []byte("Hello from Memory!"), 0644)

    // 3. Add Share backed by MemMapFs
    sm.AddShareWithFs(&protocol.Share{
        Name: "MEM", 
        Path: "/", 
        GuestAccess: true,
    }, memFs)

    // 4. Start Server
    config := &server.Config{
        Port:         8445,
        ShareManager: sm,
    }
    srv, _ := server.NewSMBServer(config)
    srv.Start()
}
```

See the runnable examples under `examples/`:

- `examples/embedded` — minimal in-memory share.
- `examples/audit_logging` — wiring up event hooks.
- `examples/timemachine` — a macOS Time Machine destination (`type=timemachine`
  share advertised over mDNS via `EnableMDNS`).

## Command Line Options

```bash
Usage: ./smbserver [options]

Core:
  -port int          Port to listen on (default 445)
  -share string      Define share (repeatable). Format: NAME:PATH[:ro]
  -auth string       Define user (repeatable). Format: user:pass or user:hash
  -config string     Path to JSON configuration file

Protocols:
  -smb string        Comma-separated list of enabled SMB versions (default "3,2,1").
                     Example: "-smb 3,2,1" or "-smb 3"
  -netbios           Enable NetBIOS support (default true)
  -netbios-port int  NetBIOS session port (default 139)
  -mdns              Advertise the server over mDNS / DNS-SD (Bonjour); default false.
                     Publishes _smb._tcp, and for Time Machine shares also
                     _device-info._tcp and _adisk._tcp so macOS auto-discovers them.

Advanced:
  -debug int         Debug level 0-10 (5=deep, 10=full)
  -log-hash          Log NTLMv2 hashes for cracking/auditing
  -mic               Enforce NTLM MIC request (default false)
  -domain string     SMB domain/workgroup name (default "WORKGROUP")
  -server string     SMB server name (default "SMB-SERVER")
  -native-os string  Custom Native OS Banner
  -native-lanman string Custom Native LanMan Banner
```

## Client Compatibility

Guest **and** authenticated access are verified against three real clients,
using a server with a guest-enabled `PUBLIC` share and an auth-only `PRIVATE`
share:

| Client | Enumerate shares | Guest → PUBLIC | Auth → PRIVATE | Guest → PRIVATE (must deny) |
|--------|:---:|:---:|:---:|:---:|
| Windows 10 (`net use` / Explorer) | ✅ | ✅ | ✅ | ✅ denied |
| Linux `smbclient` 4.19 (Samba) | ✅ | ✅ | ✅ | ✅ denied |
| macOS 26 (`smbutil` / `mount_smbfs`) | ✅ | ✅ | ✅ | ✅ denied |

Access control is enforced (guests are blocked from auth-only shares), and
clients see the share's real free/total disk space.

### macOS (Finder / Connect to Server)
- **Time Machine**: A `type: "timemachine"` share works as a backup destination end-to-end (negotiated over SMB 3.1.1). See [docs/timemachine.md](docs/timemachine.md).
- **Signing**: Correctly negotiates SMB signing requirements.
- **Spotlight**: Handles the `mdssvc` RPC pipe so Finder browsing stays stable.

### Windows
- Works with `net use`, File Explorer, and `New-SmbMapping`.
- NTLMv2 authentication; guest access works when the client honors guest logons.
- **Note**: Some Windows environments set `AllowInsecureGuestAuth=0`, which makes
  the *client* refuse unauthenticated guest logons — a client-side policy, not a
  server limitation. Authenticated access is unaffected.

### Linux (mount.cifs / smbclient)
- **smbclient**: Fully supported (listing, put, get, delete) over SMB2/SMB3.
- **mount.cifs**: Supported with both SMB2/3 (default) and SMB1 (vers=1.0).

### Impacket
- Verified end-to-end with `python3-impacket` (tested 0.11.0 and 0.13.1) across
  **SMB1, SMB2.0.2, SMB2.1, SMB3.0 and SMB3.1.1**: share enumeration, directory
  listing, upload, download (with checksum verify), mkdir/rmdir, delete,
  guest→auth-share denial, and read-only write denial — 70/70 checks pass.

## Architecture

```
cmd/smbserver/    # Main entry point, flag parsing
pkg/
├── server/       # Core server logic (Public API)
├── auth/         # NTLM crypto, hash handling
├── protocol/     # SMB packet structures
├── shares/       # Share manager, file system abstraction (afero)
├── smb1/         # SMB1 handler
├── smb2/         # SMB2/3 handler (includes Signing/Encryption stubs)
└── netbios/      # NetBIOS Name/Session services
```

## Development & Testing

Run the full test suite:
```bash
go test ./...
```

Run integration tests:
```bash
go test -v -run Integration ./test
```

## License
MIT
