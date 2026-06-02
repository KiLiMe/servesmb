package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/3xport/servesmb/pkg/protocol"
	"github.com/3xport/servesmb/pkg/server"
)

type multiFlag []string

func (m *multiFlag) String() string {
	return fmt.Sprintf("%v", *m)
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

var (
	configFile = flag.String("config", "", "Path to configuration file (optional)")
	port       = flag.Int("port", protocol.SMB_PORT, "Port to listen on")
	address    = flag.String("address", "0.0.0.0", "Address to listen on")
	// sharesPath     = flag.String("shares", "./shares", "Path to shares directory") // Removed in favor of -share
	shareFlags     multiFlag // -share NAME:PATH[:ro]
	domain         = flag.String("domain", "WORKGROUP", "SMB domain/workgroup name")
	serverName     = flag.String("server", "SMB-SERVER", "SMB server name")
	smbVersions    = flag.String("smb", "3,2,1", "SMB versions to enable (comma separated, e.g. '1,2,3' or '2,1')")
	enableNetBIOS  = flag.Bool("netbios", true, "Enable NetBIOS support")
	netbiosPort    = flag.Int("netbios-port", protocol.NETBIOS_PORT, "NetBIOS session port")
	enableMDNS     = flag.Bool("mdns", false, "Advertise the server and shares over mDNS / DNS-SD (Bonjour); Time Machine shares advertised as _adisk")
	showStats      = flag.Bool("stats", false, "Show server statistics and exit")
	showVersion    = flag.Bool("version", false, "Show version and exit")
	debugFlag      = flag.Int("debug", 0, "Debug level 0-10 (5=deep, 10=full)")
	logHash        = flag.Bool("log-hash", false, "Log NTLMv2 hash for cracking")
	staticCliChall = flag.String("static-challenge", "", "Static 16-char hex challenge (e.g. 1122334455667788)")
	mic            = flag.Bool("mic", false, "Enable NTLM MIC request (default false, use to enforce MIC)")
	nativeOS       = flag.String("native-os", "Go SMB Server", "Custom Native OS Banner")
	nativeLanMan   = flag.String("native-lanman", "Go SMB", "Custom Native LanMan Banner")
	authFlags      multiFlag
)

const VERSION = "1.0.0"

func init() {
	flag.Var(&authFlags, "auth", "Authentication user (format: 'guest', 'user:pass', or 'user:hash')")
	flag.Var(&shareFlags, "share", "Share definition (format: 'NAME:PATH[:ro][:type=timemachine]')")
}

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("SMB Server %s\n", VERSION)
		fmt.Println("Supports SMB versions 1, 2, and 3")
		os.Exit(0)
	}

	// Parse SMB versions
	var enableSMB1, enableSMB2, enableSMB3 bool
	parts := strings.Split(*smbVersions, ",")
	for _, p := range parts {
		switch strings.TrimSpace(p) {
		case "1":
			enableSMB1 = true
		case "2":
			enableSMB2 = true
		case "3":
			enableSMB3 = true
		default:
			log.Printf("Warning: Unknown SMB version '%s', ignoring", p)
		}
	}

	// Parse Users from flags
	users := make(map[string]server.AuthConfig)
	for _, authStr := range authFlags {
		if authStr == "guest" {
			users["guest"] = server.AuthConfig{Password: ""}
			continue
		}

		parts := strings.SplitN(authStr, ":", 2)
		if len(parts) != 2 {
			log.Printf("Warning: Invalid auth format '%s', expecting 'user:pass' or 'user:hash'", authStr)
			continue
		}
		username := parts[0]
		secret := parts[1]

		// check if secret is a 32-char hex string (NT Hash)
		isHash := false
		if len(secret) == 32 {
			hashBytes, err := hex.DecodeString(secret)
			if err == nil {
				users[username] = server.AuthConfig{NTHash: hashBytes}
				isHash = true
			}
		}

		if !isHash {
			users[username] = server.AuthConfig{Password: secret}
		}
	}

	// Warn if no users configured
	if len(users) == 0 {
		log.Println("Warning: No users configured (use -auth flag). Guest access might rely on 'guest' user.")
	}

	// Create configuration
	config := &server.Config{
		ListenAddress: *address,
		Port:          *port,
		SharesPath:    "", // Default to empty to allow absolute paths in shares

		Domain:          *domain,
		ServerName:      *serverName,
		EnableSMB1:      enableSMB1,
		EnableSMB2:      enableSMB2,
		EnableSMB3:      enableSMB3,
		EnableNetBIOS:   *enableNetBIOS,
		NetBIOSPort:     *netbiosPort,
		EnableMDNS:      *enableMDNS,
		Debug:           *debugFlag,
		Users:           users,
		LogHash:         *logHash,
		StaticChallenge: *staticCliChall,
		EnableMIC:       *mic,
		NativeOS:        *nativeOS,
		NativeLanMan:    *nativeLanMan,
	}

	// Load configuration file if specified
	if *configFile != "" {
		if err := loadConfig(*configFile, config); err != nil {
			log.Fatalf("Failed to load config file: %v", err)
		}
	}

	// Create SMB server
	smbServer, err := server.NewSMBServer(config)
	if err != nil {
		log.Fatalf("Failed to create SMB server: %v", err)
	}

	// Show stats and exit if requested
	if *showStats {
		stats := smbServer.GetStats()
		jsonData, err := json.MarshalIndent(stats, "", "  ")
		if err != nil {
			log.Fatalf("Failed to marshal stats: %v", err)
		}
		fmt.Println(string(jsonData))
		os.Exit(0)
	}

	// Register shares from config file
	for _, share := range config.DefinedShares {
		// Create directory if it doesn't exist
		if _, err := os.Stat(share.Path); os.IsNotExist(err) {
			if err := os.MkdirAll(share.Path, 0755); err != nil {
				log.Printf("Warning: Failed to create directory for share %s: %v", share.Name, err)
			}
		}

		if err := smbServer.AddShare(share); err != nil {
			log.Printf("Error adding config share %s: %v", share.Name, err)
		} else {
			log.Printf("Added config share %s -> %s", share.Name, share.Path)
		}
	}

	// Register command-line shares: NAME:PATH[:ro][:type=timemachine]
	// The optional 'ro' and 'type=<...>' tokens are peeled off the end (in any
	// order) so PATH may itself contain ':' (e.g. a Windows drive letter).
	for _, s := range shareFlags {
		parts := strings.Split(s, ":")
		if len(parts) < 2 {
			log.Printf("Warning: Invalid share format '%s', expecting 'NAME:PATH[:ro][:type=timemachine]'", s)
			continue
		}
		name := parts[0]
		rest := parts[1:]
		readOnly := false
		shareType := ""
		for len(rest) > 1 {
			last := rest[len(rest)-1]
			if last == "ro" {
				readOnly = true
			} else if strings.HasPrefix(last, "type=") {
				shareType = strings.TrimPrefix(last, "type=")
			} else {
				break
			}
			rest = rest[:len(rest)-1]
		}
		path := strings.Join(rest, ":")
		if path == "" {
			log.Printf("Warning: Invalid share format '%s', empty PATH", s)
			continue
		}
		if shareType != "" && shareType != "timemachine" {
			log.Printf("Warning: share %s: unknown type %q (only 'timemachine' is special); treating as a normal share", name, shareType)
		}

		// Create directory if it doesn't exist
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if err := os.MkdirAll(path, 0755); err != nil {
				log.Printf("Warning: Failed to create directory for share %s: %v", name, err)
			}
		}

		// Add share
		err := smbServer.AddShare(&protocol.Share{
			Name:        name,
			Path:        path,
			Comment:     fmt.Sprintf("%s Share", name),
			ReadOnly:    readOnly,
			GuestAccess: true, // Default to guest access for convenience
			Hidden:      false,
			Type:        shareType,
		})
		if err != nil {
			log.Printf("Error adding share %s: %v", name, err)
		} else {
			extra := ""
			if readOnly {
				extra += " [ro]"
			}
			if shareType != "" {
				extra += fmt.Sprintf(" [type=%s]", shareType)
			}
			log.Printf("Added share %s -> %s%s", name, path, extra)
		}
	}

	// Handle graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Shutting down SMB server...")
		if err := smbServer.Stop(); err != nil {
			log.Printf("Error stopping server: %v", err)
		}
		os.Exit(0)
	}()

	// Start the server
	log.Printf("Starting SMB Server %s", VERSION)
	if err := smbServer.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func loadConfig(filename string, config *server.Config) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	var fileConfig struct {
		ListenAddress string                     `json:"listen_address,omitempty"`
		Port          int                        `json:"port,omitempty"`
		SharesPath    string                     `json:"shares_path,omitempty"`
		Domain        string                     `json:"domain,omitempty"`
		ServerName    string                     `json:"server_name,omitempty"`
		EnableSMB1    *bool                      `json:"enable_smb1,omitempty"`
		EnableSMB2    *bool                      `json:"enable_smb2,omitempty"`
		EnableSMB3    *bool                      `json:"enable_smb3,omitempty"`
		EnableMDNS    *bool                      `json:"enable_mdns,omitempty"`
		Users         map[string]json.RawMessage `json:"users,omitempty"`
		Shares        []struct {
			Name        string `json:"name"`
			Path        string `json:"path"`
			Comment     string `json:"comment,omitempty"`
			ReadOnly    *bool  `json:"readonly,omitempty"`
			GuestAccess *bool  `json:"guest_access,omitempty"`
			Hidden      *bool  `json:"hidden,omitempty"`
			Type        string `json:"type,omitempty"`
		} `json:"shares,omitempty"`
	}

	if err := json.Unmarshal(data, &fileConfig); err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}

	// Apply configuration
	if fileConfig.ListenAddress != "" {
		config.ListenAddress = fileConfig.ListenAddress
	}
	if fileConfig.Port != 0 {
		config.Port = fileConfig.Port
	}
	if fileConfig.SharesPath != "" {
		config.SharesPath = fileConfig.SharesPath
	}
	if fileConfig.Domain != "" {
		config.Domain = fileConfig.Domain
	}
	if fileConfig.ServerName != "" {
		config.ServerName = fileConfig.ServerName
	}
	if fileConfig.EnableSMB1 != nil {
		config.EnableSMB1 = *fileConfig.EnableSMB1
	}
	if fileConfig.EnableSMB2 != nil {
		config.EnableSMB2 = *fileConfig.EnableSMB2
	}
	if fileConfig.EnableSMB3 != nil {
		config.EnableSMB3 = *fileConfig.EnableSMB3
	}
	if fileConfig.EnableMDNS != nil {
		config.EnableMDNS = *fileConfig.EnableMDNS
	}

	// Process Users (support both string "password" and object {"password":..., "nt_hash":...})
	if fileConfig.Users != nil {
		for u, raw := range fileConfig.Users {
			// Try as simple string first
			var password string
			if err := json.Unmarshal(raw, &password); err == nil {
				config.Users[u] = server.AuthConfig{Password: password}
				continue
			}

			// Try as object
			var userObj struct {
				Password string `json:"password,omitempty"`
				NTHash   string `json:"nt_hash,omitempty"`
			}
			if err := json.Unmarshal(raw, &userObj); err == nil {
				authConf := server.AuthConfig{Password: userObj.Password}
				if userObj.NTHash != "" {
					hashBytes, err := hex.DecodeString(userObj.NTHash)
					if err == nil && len(hashBytes) == 16 {
						authConf.NTHash = hashBytes
					} else {
						log.Printf("Warning: Invalid 32-char hex string for user %s hash", u)
					}
				}
				config.Users[u] = authConf
				continue
			}
			log.Printf("Warning: Could not parse config for user %s", u)
		}
	}

	// Process Shares
	for _, s := range fileConfig.Shares {
		readOnly := false
		if s.ReadOnly != nil {
			readOnly = *s.ReadOnly
		}
		guestAccess := true
		if s.GuestAccess != nil {
			guestAccess = *s.GuestAccess
		}
		hidden := false
		if s.Hidden != nil {
			hidden = *s.Hidden
		}
		comment := s.Comment
		if comment == "" {
			comment = fmt.Sprintf("%s Share", s.Name)
		}

		share := &protocol.Share{
			Name:        s.Name,
			Path:        s.Path,
			Comment:     comment,
			ReadOnly:    readOnly,
			GuestAccess: guestAccess,
			Hidden:      hidden,
			Type:        s.Type,
		}
		config.DefinedShares = append(config.DefinedShares, share)
	}

	log.Printf("Loaded configuration from %s", filename)
	return nil
}
