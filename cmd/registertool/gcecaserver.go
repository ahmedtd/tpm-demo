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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"path"
	"time"

	computeapiv1 "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/ahmedtd/tpm-demo/lib/tpmcapb"
	"github.com/google/go-attestation/attest"
	"github.com/google/subcommands"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type GCECAServerCommand struct {
	listenAddr        string
	machineListFile   string
	caSigningKeyFile  string
	caCertificateFile string
}

var _ subcommands.Command = (*GCECAServerCommand)(nil)

func (*GCECAServerCommand) Name() string {
	return "gce-ca-server"
}

func (*GCECAServerCommand) Synopsis() string {
	return "TODO"
}

func (*GCECAServerCommand) Usage() string {
	return `TODO`
}

func (c *GCECAServerCommand) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.listenAddr, "listen-addr", "", "The address and port to listen on.")
	f.StringVar(&c.caSigningKeyFile, "ca-signing-key", "", "The CA signing key")
	f.StringVar(&c.caCertificateFile, "ca-certificate", "", "The CA certificate")
}

func (c *GCECAServerCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := c.executeErr(ctx); err != nil {
		log.Printf("Error: %v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *GCECAServerCommand) executeErr(ctx context.Context) error {
	caSigningKey, err := ParsePEMPKCS8PrivateKey(c.caSigningKeyFile)
	if err != nil {
		return fmt.Errorf("while parsing CA signing key: %w", err)
	}

	caCertificate, err := ParsePEMCertificate(c.caCertificateFile)
	if err != nil {
		return fmt.Errorf("while parsing CA certificate: %w", err)
	}

	gceInstancesClient, err := computeapiv1.NewInstancesRESTClient(ctx)
	if err != nil {
		return fmt.Errorf("while creating GCE instances client: %w", err)
	}

	GCETPMCAService := &GCETPMCAService{
		caSigningKey:       caSigningKey,
		caCertificate:      caCertificate,
		gceInstancesClient: gceInstancesClient,
	}

	server := grpc.NewServer()
	tpmcapb.RegisterCertificateAuthorityServer(server, GCETPMCAService)

	lis, err := net.Listen("tcp", c.listenAddr)
	if err != nil {
		return fmt.Errorf("while creating listener: %w", err)
	}

	if err := server.Serve(lis); err != nil {
		return fmt.Errorf("while serving: %w", err)
	}

	return nil
}

type GCETPMCAService struct {
	tpmcapb.UnimplementedCertificateAuthorityServer

	caSigningKey  crypto.PrivateKey
	caCertificate *x509.Certificate

	gceInstancesClient *computeapiv1.InstancesClient
}

func (s *GCETPMCAService) ExchangeEKForCert(ctx context.Context, req *tpmcapb.ExchangeEKForCertRequest) (*tpmcapb.ExchangeEKForCertResponse, error) {
	var tpmVersion attest.TPMVersion
	switch req.GetTpmVersion() {
	case tpmcapb.TPMVersion_V1_2:
		tpmVersion = attest.TPMVersion12
	case tpmcapb.TPMVersion_V2_0:
		tpmVersion = attest.TPMVersion20
	default:
		return nil, status.Errorf(codes.InvalidArgument, "Only TPM Versions 1.2 and 2.0 are supported")
	}

	akPublic, err := attest.ParseAKPublic(tpmVersion, req.GetAttestationPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "while parsing AK public key: %v", err)
	}

	var ekPublic crypto.PublicKey
	if req.GetGceLookupHint() != nil {
		// Use the hint the caller provided to get the EK encryption key for
		// this GCE VM.  Nit: GCE only returns one particular EK (the RSA 2048
		// one?), but spec-compliant TPMs can also use an ECDSA P256 EK, derived
		// from the saame fixed seed.
		gceResp, err := s.gceInstancesClient.GetShieldedInstanceIdentity(ctx, &computepb.GetShieldedInstanceIdentityInstanceRequest{
			Project:  req.GetGceLookupHint().GetProject(),
			Zone:     req.GetGceLookupHint().GetZone(),
			Instance: req.GetGceLookupHint().GetInstance(),
		})
		if err != nil {
			return nil, fmt.Errorf("while calling GCE GetShieldedInstanceIdentity: %w", err)
		}

		// Extract and parse the encryption key.
		ekPublic, err = parsePEMPKIXPublicKey(gceResp.GetEncryptionKey().GetEkPub())
		if err != nil {
			return nil, fmt.Errorf("while parsing EK public key from GCE: %w", err)
		}
	} else {
		return nil, status.Errorf(codes.InvalidArgument, "gce_lookup_hint is required")
	}

	// Compose a certificate for the GCE VM identity named in the hint.  This is
	// safe because we are going to seal this certificate in a blob encrypted to
	// the TPM's EK.  If the client does not actually control this TPM, they
	// will be unable to unseal the cert.
	leafTemplate := &x509.Certificate{
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		URIs: []*url.URL{
			{
				Scheme: "tpm-based-node",
				Host: path.Join(
					"projects", req.GetGceLookupHint().GetProject(),
					"zones", req.GetGceLookupHint().GetZone(),
					"instances", req.GetGceLookupHint().GetInstance(),
				),
			},
		},
	}

	leafCert, err := x509.CreateCertificate(rand.Reader, leafTemplate, s.caCertificate, akPublic.Public, s.caSigningKey)
	if err != nil {
		return nil, fmt.Errorf("while signing leaf certificate: %w", err)
	}

	issuedCredentials := &tpmcapb.SealedCertificate{
		CertificateChain: [][]byte{leafCert},
		BeginRefreshAt:   timestamppb.New(time.Now().Add(12 * time.Hour)),
	}

	issuedCredentialsPlaintext, err := proto.Marshal(issuedCredentials)
	if err != nil {
		return nil, fmt.Errorf("while marshaling issued credentials: %w", err)
	}

	attestParams := attest.AttestationParameters{
		Public:            req.GetAttestationPublicKey(),
		CreateData:        req.GetAttestationKeyCreateData(),
		CreateAttestation: req.GetAttestationKeyCreateAttestation(),
		CreateSignature:   req.GetAttestationKeyCreateSignature(),
	}

	params := attest.ActivationParameters{
		TPMVersion: tpmVersion,
		EK:         ekPublic,
		AK:         attestParams,
	}

	// Note, we are deviating from the examples in the go-attestation library,
	// in order to implement a one-step flow.  Instead of using "secret" in a
	// two-step challenge-response protocol with the CA server, we instead use
	// "secret" as an AES-256 key to seal the certificate we issued.

	certificateSealingKey, encryptedCredentials, err := params.Generate()
	if err != nil {
		return nil, fmt.Errorf("while generating credential activation challenge: %w", err)
	}

	sealedCertificate, sealedCertificateNonce, err := seal(issuedCredentialsPlaintext, certificateSealingKey)
	if err != nil {
		return nil, fmt.Errorf("while sealing certificate: %w", err)
	}

	return &tpmcapb.ExchangeEKForCertResponse{
		Credential:             encryptedCredentials.Credential,
		Challenge:              encryptedCredentials.Secret,
		SealedCertificate:      sealedCertificate,
		SealedCertificateNonce: sealedCertificateNonce,
	}, nil
}
