package wclient

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	wowutil "github.com/acconf/wowclient/internal/secure"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"gopkg.in/ini.v1"
)

type StartupArgs struct {
	Name      string `json:"name"`
	PemFile   string `json:"pem"`
	HttpProxy string `json:"proxy"`
	WsExePath string `json:"wstunnel"`
}

type WoWClient struct {
	wrgConfig  wireGuardConfig
	wstConfig  wSTunnelConfig
	wstTunnel  *exec.Cmd
	tunDevice  tun.Device
	wrgDevice  *device.Device
	isStopping bool
}

type wSTunnelConfig struct {
	Path             string
	ConnectTo        string
	LocalToRemote    string
	TLS_SNI_Override string
	HTTP_Path_Prefix string
	HTTPProxy        string
	HTTPHeaders      []string
}

type wireGuardConfig struct {
	TunnelName          string
	PrivateKey          string
	Address             string
	DNS                 string
	PostUp              string
	PostDown            string
	PublicKey           string
	AllowedIPs          string
	Endpoint            string
	PresharedKey        string
	PersistentKeepalive string
}

func executeCommandString(commandStr string) {
	if commandStr == "" {
		return
	}
	commands := strings.Split(commandStr, ";")
	for _, cmdStr := range commands {
		cmdStr = strings.TrimSpace(cmdStr)
		if cmdStr == "" {
			continue
		}
		cmd := exec.Command("cmd", "/C", cmdStr)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: Execute command '%s' Failed: %v", cmdStr, err)
		}
	}
}
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
func keyToHex(b64Key string) (string, error) {
	dec, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(dec), nil
}
func setupNetwork(tunnelName string, conf *wireGuardConfig) error {
	addr, ipNet, err := net.ParseCIDR(conf.Address)
	if err != nil {
		return err
	}
	mask := ipNet.Mask
	subnetMask := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	err = runCommand("netsh", "interface", "ip", "set", "address", fmt.Sprintf("name=\"%s\"", tunnelName), "static", addr.String(), subnetMask)
	if err != nil {
		return err
	}
	if conf.DNS != "" {
		err = runCommand("netsh", "interface", "ip", "set", "dns", fmt.Sprintf("name=\"%s\"", tunnelName), "static", conf.DNS)
		if err != nil {
			log.Printf("Warning: Setup DNS Failed: %v", err)
		}
	}
	for _, allowedIP := range strings.Split(conf.AllowedIPs, ",") {
		allowedIP = strings.TrimSpace(allowedIP)
		_, ipNet, err := net.ParseCIDR(allowedIP)
		if err != nil {
			log.Printf("Warning: AllowedIPs '%s' is invalid: %v", allowedIP, err)
			continue
		}
		iface, err := net.InterfaceByName(tunnelName)
		if err != nil {
			return err
		}
		err = runCommand("netsh", "interface", "ip", "add", "route", ipNet.String(), fmt.Sprintf("interface=%d", iface.Index), "store=active")
		if err != nil {
			log.Printf("Warning: Fail to add route '%s' : %v", allowedIP, err)
		}
	}
	return nil
}
func cleanupNetwork(tunnelName string, conf *wireGuardConfig) {
	for _, allowedIP := range strings.Split(conf.AllowedIPs, ",") {
		allowedIP = strings.TrimSpace(allowedIP)
		_, ipNet, err := net.ParseCIDR(allowedIP)
		if err != nil {
			continue
		}
		iface, err := net.InterfaceByName(tunnelName)
		if err != nil {
			break
		}
		err = runCommand("netsh", "interface", "ip", "delete", "route", ipNet.String(), fmt.Sprintf("interface=%d", iface.Index))
		if err != nil {
			log.Printf("Warning: Failt to delete route '%s': %v", allowedIP, err)
		}
	}
}
func parsePemFile(filePath string) (*WoWClient, error) {
	decstr, err := wowutil.DecryptFile64(filePath)
	if err != nil {
		return nil, fmt.Errorf("key or config file is invalid: %w", err)
	}
	cfg, err := ini.Load(strings.NewReader(string(decstr)))
	if err != nil {
		return nil, err
	}

	appClient := &WoWClient{}

	wgConf := &appClient.wrgConfig
	interfaceSection := cfg.Section("Interface")
	wgConf.PrivateKey = interfaceSection.Key("PrivateKey").String()
	wgConf.Address = interfaceSection.Key("Address").String()
	wgConf.DNS = interfaceSection.Key("DNS").String()
	wgConf.PostUp = interfaceSection.Key("PostUp").String()
	wgConf.PostDown = interfaceSection.Key("PostDown").String()

	peerSection := cfg.Section("Peer")
	wgConf.PublicKey = peerSection.Key("PublicKey").String()
	wgConf.AllowedIPs = peerSection.Key("AllowedIPs").String()
	wgConf.Endpoint = peerSection.Key("Endpoint").String()
	wgConf.PresharedKey = peerSection.Key("PresharedKey").String()
	wgConf.PersistentKeepalive = peerSection.Key("PersistentKeepalive").String()

	if wgConf.PrivateKey == "" || wgConf.Address == "" || wgConf.PublicKey == "" || wgConf.AllowedIPs == "" || wgConf.Endpoint == "" {
		return nil, fmt.Errorf("invalid config [Interface] or [Peer] section: required keys are missing")
	}

	wsConf := &appClient.wstConfig
	wsSection := cfg.Section("WSTunnel")
	wsConf.ConnectTo = wsSection.Key("ConnectTo").String()
	wsConf.LocalToRemote = wsSection.Key("LocalToRemote").String()
	wsConf.TLS_SNI_Override = wsSection.Key("TLS_SNI_Override").String()
	wsConf.HTTP_Path_Prefix = wsSection.Key("HTTP_Path_Prefix").String()
	wsConf.HTTPHeaders = wsSection.Key("HTTPHeader").ValueWithShadows()

	return appClient, nil
}
func buildWSTunnelArgs(conf *wSTunnelConfig) []string {
	var args []string

	if conf.ConnectTo != "" {
		args = append(args, "client", conf.ConnectTo)
	}
	if conf.LocalToRemote != "" {
		args = append(args, "-L", conf.LocalToRemote)
	}
	if conf.TLS_SNI_Override != "" {
		args = append(args, "--tls-sni-override", conf.TLS_SNI_Override)
	}
	if conf.HTTP_Path_Prefix != "" {
		args = append(args, "--http-upgrade-path-prefix", conf.HTTP_Path_Prefix)
	}
	if conf.HTTPProxy != "" {
		args = append(args, "--http-proxy", conf.HTTPProxy)
	}
	for _, header := range conf.HTTPHeaders {
		args = append(args, "-H", header)
	}

	return args
}
func resolveWSTunnelExecutable(wsTunName string) (string, error) {
	wsTunPath := wsTunName
	if wsTunName == "" {
		wsTunName = "wstunnel.exe"
		exePath, err := os.Executable()
		if err != nil {
			return "", err
		}
		exeDir := filepath.Dir(exePath)
		wsTunPath = filepath.Join(exeDir, wsTunName)
	}
	wsTunPath, err := filepath.Abs(wsTunPath)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(wsTunPath); os.IsNotExist(err) {
		return "", fmt.Errorf("WSTunnel executable not found at path: %s", wsTunPath)
	}
	if _, err := exec.LookPath(wsTunPath); err != nil {
		return "", fmt.Errorf("WSTunnel executable not found in PATH: %s", wsTunPath)
	}
	return wsTunPath, nil
}
func startupWSTunnel(client *WoWClient) error {
	wstunExePath, err := resolveWSTunnelExecutable(client.wstConfig.Path)
	if err != nil {
		return err
	}
	wstArgs := buildWSTunnelArgs(&client.wstConfig)
	client.wstTunnel = exec.Command(wstunExePath, wstArgs...)
	client.wstTunnel.Stderr = os.Stderr
	err = client.wstTunnel.Start()
	if err != nil {
		return err
	}
	return nil
}
func startupWGTunnel(client *WoWClient) error {
	var err error
	client.tunDevice, err = tun.CreateTUN(client.wrgConfig.TunnelName, device.DefaultMTU)
	if err != nil {
		return err
	}

	privateKeyHex, err := keyToHex(client.wrgConfig.PrivateKey)
	if err != nil {
		return err
	}
	publicKeyHex, err := keyToHex(client.wrgConfig.PublicKey)
	if err != nil {
		return err
	}

	wgLogNm := fmt.Sprintf("(%s) ", client.wrgConfig.TunnelName)

	client.wrgDevice = device.NewDevice(client.tunDevice, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, wgLogNm))

	var uapiConfig strings.Builder
	uapiConfig.WriteString(fmt.Sprintf("private_key=%s\n", privateKeyHex))
	uapiConfig.WriteString("replace_peers=true\n")
	uapiConfig.WriteString(fmt.Sprintf("public_key=%s\n", publicKeyHex))

	if client.wrgConfig.PresharedKey != "" {
		presharedKeyHex, err := keyToHex(client.wrgConfig.PresharedKey)
		if err != nil {
			return err
		}
		uapiConfig.WriteString(fmt.Sprintf("preshared_key=%s\n", presharedKeyHex))
	}

	uapiConfig.WriteString(fmt.Sprintf("endpoint=%s\n", client.wrgConfig.Endpoint))
	for _, allowedIP := range strings.Split(client.wrgConfig.AllowedIPs, ",") {
		uapiConfig.WriteString(fmt.Sprintf("allowed_ip=%s\n", strings.TrimSpace(allowedIP)))
	}
	if client.wrgConfig.PersistentKeepalive != "" {
		uapiConfig.WriteString(fmt.Sprintf("persistent_keepalive_interval=%s\n", client.wrgConfig.PersistentKeepalive))
	}

	if err = client.wrgDevice.IpcSet(uapiConfig.String()); err != nil {
		return err
	}
	if err = client.wrgDevice.Up(); err != nil {
		return err
	}

	if err = setupNetwork(client.wrgConfig.TunnelName, &client.wrgConfig); err != nil {
		return err
	}

	executeCommandString(client.wrgConfig.PostUp)
	return nil
}

func Startup(args *StartupArgs) (*WoWClient, error) {
	// 1. parse and update config
	appClient, err := parsePemFile(args.PemFile)
	if err != nil {
		return nil, err
	}
	if args.HttpProxy != "" {
		appClient.wstConfig.HTTPProxy = args.HttpProxy
	}
	if args.WsExePath != "" {
		appClient.wstConfig.Path = args.WsExePath
	}
	if args.Name != "" {
		appClient.wrgConfig.TunnelName = strings.ToUpper(args.Name)
	}
	// 2. startup wstunnel
	err = startupWSTunnel(appClient)
	if err != nil {
		return nil, err
	}
	// 3. startup wireguard
	err = startupWGTunnel(appClient)
	if err != nil {
		return nil, err
	}
	return appClient, nil
}

func Shutdown(appClient *WoWClient) {
	if appClient.isStopping {
		return
	}
	appClient.isStopping = true

	if appClient.wstTunnel != nil && appClient.wstTunnel.Process != nil {
		if err := appClient.wstTunnel.Process.Kill(); err != nil {
			log.Printf("Warning: Fail to Shutdown wst: %v", err)
		}
	}

	if appClient.wrgDevice != nil {
		appClient.wrgDevice.Close()
	}

	if appClient.tunDevice != nil {
		appClient.tunDevice.Close()
	}

	executeCommandString(appClient.wrgConfig.PostDown)
	cleanupNetwork(appClient.wrgConfig.TunnelName, &appClient.wrgConfig)
}

func RunCmd(args *StartupArgs) {
	client, err := Startup(args)
	if err != nil {
		log.Fatalf("FATAL ERROR: %v", err)
		os.Exit(1)
	}
	log.Println("Running! Press Ctrl+C to exit.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	Shutdown(client)
}
