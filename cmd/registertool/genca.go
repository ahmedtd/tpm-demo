//  Copyright 2025 Google Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/subcommands"
)

type GenCACommand struct {
	writePrivateKeyFile    string
	writeCACertificateFile string
}

var _ subcommands.Command = (*GenCACommand)(nil)

func (*GenCACommand) Name() string {
	return "generate-ca"
}

func (*GenCACommand) Synopsis() string {
	return "TODO"
}

func (*GenCACommand) Usage() string {
	return `TODO`
}

func (c *GenCACommand) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.writePrivateKeyFile, "write-private-key", "", "Write the private key to this file.")
	f.StringVar(&c.writeCACertificateFile, "write-ca-certificate", "", "Write the CA certificate to this file.")
}

func (c *GenCACommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := c.executeErr(ctx); err != nil {
		log.Printf("Error: %v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *GenCACommand) executeErr(ctx context.Context) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("while generating key: %w", err)
	}

	privPKCS8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("while marshaling PKCS8: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privPKCS8,
	})

	caTemplate := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,

		Subject: pkix.Name{
			CommonName: "tpm-demo Certificate Authority",
		},
		NotBefore:   time.Now().Add(-5 * time.Minute),
		NotAfter:    time.Now().Add(30 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{},
	}

	caCertificate, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, pub, priv)
	if err != nil {
		return fmt.Errorf("while signing root CA certificate: %w", err)
	}

	caCertificatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertificate,
	})

	if err := os.WriteFile(c.writePrivateKeyFile, privPEM, 0600); err != nil {
		return fmt.Errorf("while writing private key to file: %w", err)
	}

	if err := os.WriteFile(c.writeCACertificateFile, caCertificatePEM, 0640); err != nil {
		return fmt.Errorf("while writing CA certificate to file: %w", err)
	}

	return nil
}
