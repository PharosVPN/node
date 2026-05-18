// SPDX-License-Identifier: AGPL-3.0-or-later
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
	"testing"
	"time"

	buoyv1 "github.com/PharosVPN/buoy/internal/gen/pharos/buoy/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// TestServeAcceptsMutualTLS proves a client whose certificate chains to the
// CA reaches the service: every RPC is wired and returns Unimplemented in B1.
func TestServeAcceptsMutualTLS(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.writeNodeFiles(t, dir)
	addr := freeAddr(t)

	srv, err := NewServer(addr,
		filepath.Join(dir, "node.crt"),
		filepath.Join(dir, "node.key"),
		filepath.Join(dir, "ca.crt"),
		discardLogger())
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
	_, err = buoyv1.NewNodeControlClient(conn).GetStatus(context.Background(), &buoyv1.GetStatusRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("GetStatus over mTLS: got %v, want Unimplemented", err)
	}
}

// TestServeRejectsNonMTLS proves a client presenting no certificate is dropped
// at the TLS handshake — no banner, no application response (DESIGN §3).
func TestServeRejectsNonMTLS(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.writeNodeFiles(t, dir)
	addr := freeAddr(t)

	srv, err := NewServer(addr,
		filepath.Join(dir, "node.crt"),
		filepath.Join(dir, "node.key"),
		filepath.Join(dir, "ca.crt"),
		discardLogger())
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
	_, err = buoyv1.NewNodeControlClient(conn).GetStatus(rpcCtx, &buoyv1.GetStatusRequest{})
	if err == nil {
		t.Fatal("GetStatus without a client certificate succeeded, want handshake failure")
	}
}

// --- test helpers -----------------------------------------------------------

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

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

// writeNodeFiles writes node.crt, node.key and ca.crt into dir, as helm's
// onboarding would.
func (ca *testCA) writeNodeFiles(t *testing.T, dir string) {
	t.Helper()
	certPEM, keyPEM := ca.leaf(t, "pharos-buoy-node", x509.ExtKeyUsageServerAuth,
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
	certPEM, keyPEM := ca.leaf(t, "helm-controller", x509.ExtKeyUsageClientAuth, nil)
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
