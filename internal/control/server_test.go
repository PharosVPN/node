// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PharosVPN/node/internal/awg"
	nodev1 "github.com/PharosVPN/node/internal/gen/pharos/node/v1"
	"github.com/PharosVPN/node/internal/netpolicy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// noopNetExec / noopNetEgress let the control tests build a real netpolicy
// Applier without touching the system firewall.
type noopNetExec struct{}

func (noopNetExec) Run(context.Context, []string) error { return nil }

type noopNetEgress struct{}

func (noopNetEgress) DefaultEgress(context.Context) (string, error) { return "eth0", nil }

// TestServeAcceptsMutualTLS proves a client whose certificate chains to the
// CA reaches the service, and that GetStatus reports the node's AmneziaWG
// identity — the values coxswain needs before it will provision devices.
func TestServeAcceptsMutualTLS(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.writeNodeFiles(t, dir)
	addr := freeAddr(t)

	srv, err := NewServer(testOptions(t, dir, addr))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	conn := dial(t, addr, ca.clientCreds(t))
	resp, err := nodev1.NewNodeControlClient(conn).GetStatus(context.Background(), &nodev1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus over mTLS: %v", err)
	}
	if resp.GetAgentVersion() != "test-version" {
		t.Errorf("agent_version = %q, want test-version", resp.GetAgentVersion())
	}
	awgInfo := resp.GetAmneziawg()
	if awgInfo == nil {
		t.Fatal("GetStatus returned no amneziawg info")
	}
	if awgInfo.GetPublicKey() == "" {
		t.Error("amneziawg.public_key is empty")
	}
	if obf := awgInfo.GetObfuscation(); obf == nil || obf.GetJmin() >= obf.GetJmax() {
		t.Errorf("amneziawg.obfuscation invalid: %+v", obf)
	}

	// SetNetworkConfig (decision 16) is implemented: an empty policy (forward
	// off) applies cleanly with no rules.
	npResp, err := nodev1.NewNodeControlClient(conn).SetNetworkConfig(context.Background(),
		&nodev1.SetNetworkConfigRequest{Config: &nodev1.NetworkConfig{}})
	if err != nil {
		t.Errorf("SetNetworkConfig: %v", err)
	} else if !npResp.GetApplied() {
		t.Error("SetNetworkConfig: applied = false, want true")
	}
}

// TestServeInnerLink exercises the node-cascade inner-link RPCs end to end over
// mTLS: configure an inner link toward an exit (the entry dials it), reject a
// config with no endpoint, then tear the link down.
func TestServeInnerLink(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.writeNodeFiles(t, dir)
	addr := freeAddr(t)

	srv, err := NewServer(testOptions(t, dir, addr))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	client := nodev1.NewNodeControlClient(dial(t, addr, ca.clientCreds(t)))

	// A valid exit obfuscation set: distinct H >= 5, Jmin <= Jmax, S2 != S1+56.
	exitObf := &nodev1.AmneziaWGObfuscation{
		Jc: 5, Jmin: 25, Jmax: 800, S1: 20, S2: 30, S3: 40, S4: 50,
		H1: 10, H2: 11, H3: 12, H4: 13,
	}
	resp, err := client.ConfigureInnerLink(context.Background(), &nodev1.ConfigureInnerLinkRequest{
		Revision: 1,
		Config: &nodev1.InnerLinkConfig{
			Interface:       "awg1",
			ListenPort:      51820,
			Mtu:             1380,
			PeerObfuscation: exitObf,
			Exit: &nodev1.Peer{
				Protocol:   nodev1.Protocol_PROTOCOL_AMNEZIAWG,
				PublicKey:  "EXITPUB=",
				AllowedIps: []string{"0.0.0.0/0"},
				Endpoints:  []string{"198.51.100.9:443"},
			},
		},
	})
	if err != nil {
		t.Fatalf("ConfigureInnerLink: %v", err)
	}
	if resp.GetAppliedRevision() != 1 || !resp.GetReloaded() {
		t.Errorf("ConfigureInnerLink resp = %+v, want applied=1 reloaded=true", resp)
	}

	// The inner conf carries the exit endpoint and the exit's obfuscation.
	raw, err := os.ReadFile(filepath.Join(dir, "awg1.conf"))
	if err != nil {
		t.Fatalf("read awg1.conf: %v", err)
	}
	for _, want := range []string{"Endpoint = 198.51.100.9:443", "ListenPort = 51820", "H1 = 10"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("awg1.conf missing %q:\n%s", want, raw)
		}
	}

	// An exit with no endpoint is rejected — the entry must know where to dial.
	_, err = client.ConfigureInnerLink(context.Background(), &nodev1.ConfigureInnerLinkRequest{
		Revision: 1,
		Config: &nodev1.InnerLinkConfig{
			Interface:       "awg2",
			ListenPort:      51821,
			PeerObfuscation: exitObf,
			Exit:            &nodev1.Peer{PublicKey: "X=", AllowedIps: []string{"0.0.0.0/0"}},
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("ConfigureInnerLink without endpoint: got %v, want InvalidArgument", err)
	}

	// Teardown removes the interface and its conf.
	rm, err := client.RemoveInnerLink(context.Background(), &nodev1.RemoveInnerLinkRequest{Interface: "awg1"})
	if err != nil {
		t.Fatalf("RemoveInnerLink: %v", err)
	}
	if !rm.GetRemoved() {
		t.Error("RemoveInnerLink: removed = false")
	}
	if _, err := os.Stat(filepath.Join(dir, "awg1.conf")); !os.IsNotExist(err) {
		t.Errorf("RemoveInnerLink must delete the conf, stat err = %v", err)
	}
}

// TestServeRejectsNonMTLS proves a client presenting no certificate is dropped
// at the TLS handshake — no banner, no application response (DESIGN §3).
func TestServeRejectsNonMTLS(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.writeNodeFiles(t, dir)
	addr := freeAddr(t)

	srv, err := NewServer(testOptions(t, dir, addr))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	// A client trusting the CA but presenting no client certificate.
	noCertCreds := credentials.NewTLS(&tls.Config{
		RootCAs:    ca.pool(),
		MinVersion: tls.VersionTLS13,
	})
	conn := dial(t, addr, noCertCreds)
	rpcCtx, rpcCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer rpcCancel()
	_, err = nodev1.NewNodeControlClient(conn).GetStatus(rpcCtx, &nodev1.GetStatusRequest{})
	if err == nil {
		t.Fatal("GetStatus without a client certificate succeeded, want handshake failure")
	}
}

// --- test helpers -----------------------------------------------------------

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testOptions builds Server options for a node whose mTLS files live in dir.
// It wires a minimal AmneziaWG Manager backed by a stub Runtime — enough for
// GetStatus and the unimplemented RPCs in B2's test surface.
func testOptions(t *testing.T, dir, addr string) Options {
	t.Helper()
	node, err := awg.Load(filepath.Join(dir, "awg-node.json"))
	if err != nil {
		t.Fatalf("awg.Load: %v", err)
	}
	mgr, err := awg.NewManager(awg.ManagerOptions{
		Node:         node,
		Runtime:      &stubRuntime{},
		ConfPath:     filepath.Join(dir, "awg0.conf"),
		RevisionPath: filepath.Join(dir, "awg-revision"),
	})
	if err != nil {
		t.Fatalf("awg.NewManager: %v", err)
	}
	netPol, err := netpolicy.New(netpolicy.Options{
		WGIface:   "awg0",
		Exec:      noopNetExec{},
		Egress:    noopNetEgress{},
		StatePath: filepath.Join(dir, "netpolicy.json"),
		Log:       discardLogger(),
	})
	if err != nil {
		t.Fatalf("netpolicy.New: %v", err)
	}
	return Options{
		ListenAddr:   addr,
		NodeCertPath: filepath.Join(dir, "node.crt"),
		NodeKeyPath:  filepath.Join(dir, "node.key"),
		CACertPath:   filepath.Join(dir, "ca.crt"),
		Version:      "test-version",
		AWGNode:      node,
		AWGRegistry:  awg.NewRegistry(mgr, innerFactory(dir)),
		NetPolicy:    netPol,
		Log:          discardLogger(),
	}
}

// innerFactory builds inner-link managers backed by the stub runtime, with
// conf/revision under dir — the test analogue of run.go's production factory.
func innerFactory(dir string) awg.ManagerFactory {
	return func(iface string, spec awg.InterfaceSpec) (*awg.Manager, error) {
		s := spec
		return awg.NewManager(awg.ManagerOptions{
			Interface:    iface,
			Spec:         &s,
			Runtime:      stubRuntime{},
			ConfPath:     filepath.Join(dir, iface+".conf"),
			RevisionPath: filepath.Join(dir, iface+"-revision"),
		})
	}
}

// stubRuntime is a minimal awg.Runtime for control-level tests: it reports
// the interface as down and answers Show with no peers. The data-plane
// orchestration is tested under package awg with a richer fake.
type stubRuntime struct{}

func (stubRuntime) Up(context.Context, string) error       { return nil }
func (stubRuntime) Down(context.Context, string) error     { return nil }
func (stubRuntime) SyncConf(context.Context, string) error { return nil }
func (stubRuntime) AddPeer(context.Context, string, string, []string, string) error {
	return nil
}
func (stubRuntime) RemovePeer(context.Context, string) error     { return nil }
func (stubRuntime) AddRoute(context.Context, string) error       { return nil }
func (stubRuntime) RemoveRoute(context.Context, string) error    { return nil }
func (stubRuntime) Show(context.Context) ([]awg.LivePeer, error) { return nil, nil }
func (stubRuntime) Listening(context.Context) (bool, error)      { return false, nil }

func freeAddr(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := lis.Addr().String()
	if err := lis.Close(); err != nil {
		t.Fatalf("close reservation: %v", err)
	}
	return addr
}

func dial(t *testing.T, addr string, creds credentials.TransportCredentials) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// testCA is a minimal single-tier certificate authority for tests: it signs a
// node server certificate and a controller client certificate.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func (ca *testCA) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.pem)
	return pool
}

// leaf signs a leaf certificate for the given extended key usage, returning
// PEM cert and key bytes.
func (ca *testCA) leaf(t *testing.T, cn string, eku x509.ExtKeyUsage, ips []net.IP) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{eku},
		BasicConstraintsValid: true,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// writeNodeFiles writes node.crt, node.key and ca.crt into dir, as coxswain's
// onboarding would.
func (ca *testCA) writeNodeFiles(t *testing.T, dir string) {
	t.Helper()
	certPEM, keyPEM := ca.leaf(t, "pharos-node-node", x509.ExtKeyUsageServerAuth,
		[]net.IP{net.IPv4(127, 0, 0, 1)})
	write := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("node.crt", certPEM)
	write("node.key", keyPEM)
	write("ca.crt", ca.pem)
}

// clientCreds builds mTLS credentials for a controller-style client.
func (ca *testCA) clientCreds(t *testing.T) credentials.TransportCredentials {
	t.Helper()
	certPEM, keyPEM := ca.leaf(t, "coxswain-controller", x509.ExtKeyUsageClientAuth, nil)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      ca.pool(),
		MinVersion:   tls.VersionTLS13,
	})
}
