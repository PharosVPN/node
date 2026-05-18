// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package control is buoy's mTLS gRPC server: the NodeControl service helm
// drives. buoy is the server and helm is the client — helm dials in over
// outbound mTLS and buoy opens no connection to helm (DESIGN §2, §6).
//
// The listener accepts only mTLS connections whose client certificate chains
// to the root CA. Anything else is rejected at the TLS handshake — no banner,
// no application-level response.
package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"

	buoyv1 "github.com/PharosVPN/buoy/internal/gen/pharos/buoy/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Server is buoy's NodeControl gRPC server.
type Server struct {
	addr string
	grpc *grpc.Server
	log  *slog.Logger
}

// NewServer builds a NodeControl server bound to addr.
//
//   - nodeCertPath holds the node's leaf certificate followed by the Fleet
//     intermediate; nodeKeyPath holds its matching private key.
//   - caCertPath holds the root CA — client certificates must chain to it.
//
// The returned server is not yet listening; call Serve.
func NewServer(addr, nodeCertPath, nodeKeyPath, caCertPath string, log *slog.Logger) (*Server, error) {
	tlsCfg, err := serverTLS(nodeCertPath, nodeKeyPath, caCertPath)
	if err != nil {
		return nil, err
	}

	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	buoyv1.RegisterNodeControlServer(gs, newService())

	return &Server{addr: addr, grpc: gs, log: log}, nil
}

// Serve binds the listener and serves until ctx is cancelled, then stops
// gracefully. It returns nil on a clean shutdown.
func (s *Server) Serve(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("control: listen on %s: %w", s.addr, err)
	}
	s.log.Info("NodeControl server listening", "addr", lis.Addr().String())

	errCh := make(chan error, 1)
	go func() { errCh <- s.grpc.Serve(lis) }()

	select {
	case <-ctx.Done():
		s.log.Info("shutting down NodeControl server")
		s.grpc.GracefulStop()
		return nil
	case err := <-errCh:
		if errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return fmt.Errorf("control: serve: %w", err)
	}
}

// serverTLS builds the mTLS configuration: buoy presents its node chain and
// requires a client certificate that verifies against the root CA.
func serverTLS(nodeCertPath, nodeKeyPath, caCertPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(nodeCertPath, nodeKeyPath)
	if err != nil {
		return nil, fmt.Errorf("control: load node certificate: %w", err)
	}

	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("control: read CA certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("control: no certificates in CA file")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    roots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
