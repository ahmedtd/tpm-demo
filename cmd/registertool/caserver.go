package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/ahmedtd/tpm-demo/lib/machinedbpb"
	"github.com/ahmedtd/tpm-demo/lib/tpmcapb"
	"github.com/google/go-attestation/attest"
	"github.com/google/subcommands"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type CAServerCommand struct {
	listenAddr        string
	machineListFile   string
	caSigningKeyFile  string
	caCertificateFile string
}

var _ subcommands.Command = (*CAServerCommand)(nil)

func (*CAServerCommand) Name() string {
	return "ca-server"
}

func (*CAServerCommand) Synopsis() string {
	return "TODO"
}

func (*CAServerCommand) Usage() string {
	return `TODO`
}

func (c *CAServerCommand) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.listenAddr, "listen-addr", "", "The address and port to listen on.")
	f.StringVar(&c.machineListFile, "machine-list", "", "A file containing MachineDB textprotos.")
	f.StringVar(&c.caSigningKeyFile, "ca-signing-key", "", "The CA signing key")
	f.StringVar(&c.caCertificateFile, "ca-certificate", "", "The CA certificate")
}

func (c *CAServerCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := c.executeErr(ctx); err != nil {
		log.Printf("Error: %v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *CAServerCommand) executeErr(ctx context.Context) error {
	mdb, err := MachineDBFromTextProtoFile(c.machineListFile)
	if err != nil {
		return fmt.Errorf("while loading static machine list: %w", err)
	}

	caSigningKey, err := ParsePEMPKCS8PrivateKey(c.caSigningKeyFile)
	if err != nil {
		return fmt.Errorf("while parsing CA signing key: %w", err)
	}

	caCertificate, err := ParsePEMCertificate(c.caCertificateFile)
	if err != nil {
		return fmt.Errorf("while parsing CA certificate: %w", err)
	}

	tpmCAService := &TPMCAService{
		machineDB:     mdb,
		caSigningKey:  caSigningKey,
		caCertificate: caCertificate,
	}

	server := grpc.NewServer()
	tpmcapb.RegisterCertificateAuthorityServer(server, tpmCAService)

	lis, err := net.Listen("tcp", c.listenAddr)
	if err != nil {
		return fmt.Errorf("while creating listener: %w", err)
	}

	if err := server.Serve(lis); err != nil {
		return fmt.Errorf("while serving: %w", err)
	}

	return nil
}

func ParsePEMPKCS8PrivateKey(fname string) (crypto.PrivateKey, error) {
	pemBytes, err := os.ReadFile(fname)
	if err != nil {
		return nil, fmt.Errorf("while reading file: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM blocks in file")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("PEM block has wrong type")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("while parsing PKCS#8 private key: %w", err)
	}

	return key, nil
}

func ParsePEMCertificate(fname string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(fname)
	if err != nil {
		return nil, fmt.Errorf("while reading file: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM blocks in file")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block has wrong type")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("while parsing certificate: %w", err)
	}

	return cert, nil
}

type StaticMachineDB struct {
	Entries []*machinedbpb.Machine
}

func (s *StaticMachineDB) EntryForEndorsementKey(ekpkix []byte) (*machinedbpb.Machine, bool) {
	for _, ent := range s.Entries {
		if bytes.Equal(ent.GetEndorsementPublicKeyPkix(), ekpkix) {
			return ent, true
		}
	}
	return nil, false
}

func MachineDBFromTextProtoFile(fname string) (*StaticMachineDB, error) {
	dbBytes, err := os.ReadFile(fname)
	if err != nil {
		return nil, fmt.Errorf("while reading file: %w", err)
	}

	db := &machinedbpb.MachineList{}
	if err := prototext.Unmarshal(dbBytes, db); err != nil {
		return nil, fmt.Errorf("while unmarshaling textproto: %w", err)
	}

	return &StaticMachineDB{
		Entries: db.GetMachines(),
	}, nil
}

type TPMCAService struct {
	tpmcapb.UnimplementedCertificateAuthorityServer

	caSigningKey  crypto.PrivateKey
	caCertificate *x509.Certificate

	machineDB *StaticMachineDB
}

func (s *TPMCAService) ExchangeEKForCert(ctx context.Context, req *tpmcapb.ExchangeEKForCertRequest) (*tpmcapb.ExchangeEKForCertResponse, error) {
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

	machine, ok := s.machineDB.EntryForEndorsementKey(req.GetEndorsementPublicKey())
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "no machine db entry for this endorsement key")
	}

	leafTemplate := &x509.Certificate{
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		URIs: []*url.URL{
			{
				Scheme: "tpm-based-node",
				Host:   machine.GetNodeName(),
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

	ekPublic, err := x509.ParsePKIXPublicKey(req.GetEndorsementPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "while parsing endorsement public key: %v", err)
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

func seal(plaintext, key []byte) ( /*ciphertext*/ []byte /*nonce*/, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("while creating AES cipher: %w", err)
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("while generating random nonce: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("while creating AEAD: %w", err)
	}

	sealedState := aesgcm.Seal(nil, nonce, plaintext, nil)

	return sealedState, nonce, nil
}
