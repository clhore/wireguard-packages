package wgconf

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/clhore/wireguard-packages/wgkeys"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type IPAddrAndMac struct {
	IpAddr   string
	MaskAddr int
}

type Endpoint struct {
	Host string
	Port int
}

type Peer struct {
	PublicKey  string
	Endpoint   Endpoint
	AllowedIPs []string
	KeepAlive  int
}

type WireGuardTrun struct {
	InterfaceName string
	PrivateKey    string
	ListenPort    int
	Address       IPAddrAndMac
	cfg           wgtypes.Config
}

func NewWireGuardTrun(options ...func(*WireGuardTrun)) (*WireGuardTrun, error) {
	var err error
	wg := &WireGuardTrun{
		InterfaceName: "wg0",
		ListenPort:    51820,
		Address:       IPAddrAndMac{},
		cfg:           wgtypes.Config{},
	}

	for _, opt := range options {
		opt(wg)
	}

	if wg.PrivateKey == "" && func() bool {
		wg.PrivateKey, err = wgkeys.GeneratePrivateKey()
		return err != nil
	}() {
		return nil, err
	}

	return wg, nil
}

func WithInterfaceName(ifaceName string) func(*WireGuardTrun) {
	return func(wg *WireGuardTrun) {
		wg.InterfaceName = ifaceName
	}
}

func WithPrivateKey(privateKey string) func(*WireGuardTrun) {
	return func(wg *WireGuardTrun) {
		wg.PrivateKey = privateKey
	}
}

func WithListenPort(port int) func(*WireGuardTrun) {
	return func(wg *WireGuardTrun) {
		wg.ListenPort = port
	}
}

func WithInterfaceIp(address IPAddrAndMac) func(*WireGuardTrun) {
	return func(wg *WireGuardTrun) {
		wg.Address = address
	}
}

func (wg *WireGuardTrun) getPublicKey() (string, error) {
	return wgkeys.GeneratePublicKey(wg.PrivateKey)
}

func (wg *WireGuardTrun) CreateInterface() error {
	if _, err := wg.SearchInterface(); err == nil {
		return fmt.Errorf("error interface %s does exist", wg.InterfaceName)
	}

	ifaceConf := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{
			Name: wg.InterfaceName,
		},
		LinkType: "wireguard",
	}

	if err := netlink.LinkAdd(ifaceConf); err != nil {
		return fmt.Errorf("error create interface %s: %w", wg.InterfaceName, err)
	}

	if err := netlink.LinkSetUp(ifaceConf); err != nil {
		return fmt.Errorf("error UP interface %s: %w", wg.InterfaceName, err)
	}

	if err := wg.SetInterfaceWgTrun(); err != nil {
		return fmt.Errorf("error setup interface %s: %w", wg.InterfaceName, err)
	}

	ipAddr, err := wg.SetInterfaceIP()
	if err != nil {
		return fmt.Errorf("error set IP %s to interface %s: %w", ipAddr, wg.InterfaceName, err)
	}

	return nil
}

func (wg *WireGuardTrun) SearchInterface() (netlink.Link, error) {
	iface, err := netlink.LinkByName(wg.InterfaceName)
	if err != nil {
		return iface, fmt.Errorf("interface %s does not exist: %w", wg.InterfaceName, err)
	}
	return iface, nil
}

func (wg *WireGuardTrun) SetInterfaceIP() (string, error) {
	iface, err := wg.SearchInterface()
	if err != nil {
		return "", err
	}

	ipAddr := wg.Address.IpAddr + "/" + strconv.Itoa(wg.Address.MaskAddr)

	addr, err := netlink.ParseAddr(ipAddr)
	if err != nil {
		return ipAddr, fmt.Errorf("error parse addr %s: %w", ipAddr, err)
	}

	if err := netlink.AddrAdd(iface, addr); err != nil {
		return ipAddr, fmt.Errorf("error add addr %s to interface %s: %w", ipAddr, wg.InterfaceName, err)
	}

	return ipAddr, nil
}

func (wg *WireGuardTrun) SetInterfaceWgTrun() error {
	// Crear cliente WireGuard
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("error creando el cliente wgctrl: %w", err)
	}
	defer client.Close()

	// Parsear claves
	privKey, err := wgtypes.ParseKey(wg.PrivateKey)
	if err != nil {
		return fmt.Errorf("error parseando la clave privada: %w", err)
	}

	// Configurar la interfaz WireGuard
	wg.cfg = wgtypes.Config{
		PrivateKey: &privKey,
		ListenPort: &wg.ListenPort,
	}

	if err := client.ConfigureDevice(wg.InterfaceName, wg.cfg); err != nil {
		return fmt.Errorf("error al configurar la interfaz %s: %w", wg.InterfaceName, err)
	}

	return nil
}

func (wg *WireGuardTrun) UpdateConfigInterfaceWgTrun() error {
	// Crear cliente WireGuard
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("error creando el cliente wgctrl: %w", err)
	}
	defer client.Close()

	if err := client.ConfigureDevice(wg.InterfaceName, wg.cfg); err != nil {
		return fmt.Errorf("error al configurar la interfaz %s: %w", wg.InterfaceName, err)
	}

	return nil
}

func (wg *WireGuardTrun) AddPeer(peer Peer) error {
	peerKey, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		return fmt.Errorf("error parseando la clave pública del peer: %w", err)
	}

	var allowedIPs []net.IPNet
	for _, ip := range peer.AllowedIPs {
		_, ipnet, err := net.ParseCIDR(ip)
		if err != nil {
			return fmt.Errorf("error al parsear AllowedIPs: %w", err)
		}
		allowedIPs = append(allowedIPs, *ipnet)
	}

	endpoint := &net.UDPAddr{
		IP:   net.ParseIP(peer.Endpoint.Host),
		Port: peer.Endpoint.Port,
	}

	newPeer := wgtypes.PeerConfig{
		PublicKey:                   peerKey,
		Endpoint:                    endpoint,
		AllowedIPs:                  allowedIPs,
		PersistentKeepaliveInterval: func() *time.Duration { d := time.Duration(peer.KeepAlive) * time.Second; return &d }(),
	}

	wg.cfg.Peers = append(wg.cfg.Peers, newPeer)

	return nil
}

func (wg *WireGuardTrun) RemovePeer(peerPublicKey string) error {
	peerKey, err := wgtypes.ParseKey(peerPublicKey)
	if err != nil {
		return fmt.Errorf("error parse public key")
	}

	for i, peer := range wg.cfg.Peers {
		if peer.PublicKey == peerKey {
			wg.cfg.Peers = append(wg.cfg.Peers[:i], wg.cfg.Peers[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("error search peer %s", peerPublicKey)
}

func (wg *WireGuardTrun) ListPeers() ([]string, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("error creando el cliente wgctrl: %w", err)
	}
	defer client.Close()

	device, err := client.Device(wg.InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("error obteniendo el dispositivo %s: %w", wg.InterfaceName, err)
	}

	var peers []string
	for _, peer := range device.Peers {
		peers = append(peers, peer.PublicKey.String())
	}

	return peers, nil
}

func (wg *WireGuardTrun) DeleteInterface() error {
	iface, err := wg.SearchInterface()
	if err != nil {
		return fmt.Errorf("error search interface")
	}

	if err := netlink.LinkDel(iface); err != nil {
		return fmt.Errorf("error delete interface %s", wg.InterfaceName)
	}
	return nil
}
