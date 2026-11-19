// Copyright 2026 The Agent Substrate Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package ateapiclient dials substrate's ate-api-server over mutual TLS. It is
// a copy of the parts of substrate's internal/ateapiauth this provider needs.
package ateapiclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"plugins.go.ate.dev/credprovider-token-exchange/internal/credbundle"
)

const roundRobinServiceConfig = `{"loadBalancingConfig": [{"round_robin":{}}]}`

// Config names the files and server name used to dial ate-api-server.
type Config struct {
	Address string
	// CAFile is the trust bundle the server certificate must chain to.
	CAFile string
	// ServerName is the DNS name the server certificate must carry.
	ServerName string
	// ClientCredBundle is the credential bundle presented as the client
	// certificate.
	ClientCredBundle string
}

// Dial returns a client connection to ate-api-server. Both bundles must be
// readable now, so a missing projection fails startup, and both are re-read
// when they change, so rotations apply to new connections.
func Dial(cfg Config) (*grpc.ClientConn, error) {
	switch {
	case cfg.Address == "":
		return nil, errors.New("ateapi address is required")
	case cfg.CAFile == "":
		return nil, errors.New("ateapi CA file is required")
	case cfg.ServerName == "":
		return nil, errors.New("ateapi server name is required")
	case cfg.ClientCredBundle == "":
		return nil, errors.New("ateapi client credential bundle is required")
	}
	loadRootCAs := credbundle.PoolLoader(cfg.CAFile)
	if _, err := loadRootCAs(); err != nil {
		return nil, fmt.Errorf("ateapi CA file: %w", err)
	}
	clientCert := credbundle.ClientLoader(cfg.ClientCredBundle)
	if _, err := clientCert(nil); err != nil {
		return nil, fmt.Errorf("ateapi client credential bundle: %w", err)
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: cfg.ServerName,
		// The chain is verified in VerifyConnection against the reloadable
		// pool, so a CA rotation applies without a restart.
		InsecureSkipVerify:   true, //nolint:gosec
		GetClientCertificate: clientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			pool, err := loadRootCAs()
			if err != nil {
				return err
			}
			if len(cs.PeerCertificates) == 0 {
				return errors.New("ate-api-server presented no certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			_, err = cs.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots:         pool,
				Intermediates: inter,
				DNSName:       cfg.ServerName,
			})
			return err
		},
	}
	return grpc.NewClient(cfg.Address,
		grpc.WithDefaultServiceConfig(roundRobinServiceConfig),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
}
