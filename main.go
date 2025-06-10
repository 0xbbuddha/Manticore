package main

import (
	"fmt"
	"net"

	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/goopts/parser"
)

var (
	mode string

	// Configuration
	debug bool

	// Network settings
	target string

	// Authentication details
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string
	authNoPass   bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{
		Banner: "poc - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0",
	}

	ap.NewBoolArgument(&debug, "", "--debug", false, "Enable debug mode.")

	// Network settings
	subparser_list_group_network, err := ap.NewArgumentGroup("Network")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_list_group_network.NewStringArgument(&target, "", "--target", "", false, "IP Address of the target host.")
	}
	// Authentication
	subparser_list_group_auth, err := ap.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_list_group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", false, "(FQDN) domain to authenticate to.")
		subparser_list_group_auth.NewStringArgument(&authUsername, "-u", "--user", "", false, "User to authenticate with.")
	}
	// Secret
	subparser_list_group_secret, err := ap.NewRequiredMutuallyExclusiveArgumentGroup("Secret")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		subparser_list_group_secret.NewBoolArgument(&authNoPass, "", "--no-pass", false, "Don't ask for password (useful for -k).")
		subparser_list_group_secret.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		subparser_list_group_secret.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
		subparser_list_group_secret.NewStringArgument(&authHashes, "", "--aes-key", "", false, "AES key to use for Kerberos Authentication (128 or 256 bits).")
	}

	// Parse arguments
	ap.Parse()
}

func main() {
	parseArgs()

	c := client.NewClientUsingTCPTransport(net.ParseIP(target), 445)

	err := c.Connect(net.ParseIP(target), 445)
	if err != nil {
		fmt.Printf("[error] Error connecting to SMB server: %s\n", err)
		return
	} else {
		fmt.Printf("[info] Connected to SMB server\n")
	}

	fmt.Printf("[info] Dialect         : [%s]\n", c.Connection.SelectedDialect)
	fmt.Printf("[info] Capabilities    : [0x%08x] (%s)\n", uint32(c.Connection.Server.Capabilities), c.Connection.Server.Capabilities.String())
	fmt.Printf("[info] Session key     : [0x%08x]\n", c.Connection.Server.SessionKey)
	fmt.Printf("[info] Max buffer size : [0x%08x] (%d)\n", c.Connection.Server.MaxBufferSize, c.Connection.Server.MaxBufferSize)
	fmt.Printf("[info] Max mpx count   : [0x%04x] (%d)\n", c.Connection.MaxMpxCount, c.Connection.MaxMpxCount)
	fmt.Printf("[info] System time     : [0x%08x]\n", c.Connection.Server.SystemTime.ToInt64())
	fmt.Printf("[info] System time     : [%s]\n", c.Connection.Server.SystemTime.GetTime())
	fmt.Printf("[info] Time zone       : [%d]\n", c.Connection.Server.TimeZone)
	fmt.Printf("[info] SecurityMode    : [0x%02x] (%s)\n", uint8(c.Connection.Server.SecurityMode), c.Connection.Server.SecurityMode.String())
	if c.Connection.Server.SecurityMode.SupportsChallengeResponseAuth() {
		fmt.Printf("[info] Server GUID     : [%s]\n", c.Connection.Server.ServerGUID.ToFormatD())
	} else {
		fmt.Printf("[info] Domain name     : [%s]\n", c.Connection.Server.DomainName)
		fmt.Printf("[info] Server name     : [%s]\n", c.Connection.Server.Name)
	}

	c.Session = &client.Session{
		Client: c,
		Credentials: &credentials.Credentials{
			Domain:   authDomain,
			Username: authUsername,
			Password: authPassword,
		},
	}
	err = c.Session.SessionSetup()
	if err != nil {
		fmt.Printf("[error] Error setting up session: %s\n", err)
		return
	}
}
