package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ahmedtd/tpm-demo/lib/tpmcapb"
	"github.com/google/go-attestation/attest"
	"github.com/google/subcommands"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

type CAClientCommand struct {
	attestationKeyFile string
	caAddress          string
}

var _ subcommands.Command = (*CAClientCommand)(nil)

func (*CAClientCommand) Name() string {
	return "ca-client"
}

func (*CAClientCommand) Synopsis() string {
	return "TODO"
}

func (*CAClientCommand) Usage() string {
	return `TODO`
}

func (c *CAClientCommand) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.attestationKeyFile, "attestation-key-file", "", "The file in which the generated attestation key should be stored.")
	f.StringVar(&c.caAddress, "ca-address", "", "The dial address for the CA service")
}

func (c *CAClientCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := c.executeErr(ctx); err != nil {
		log.Printf("Error: %v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *CAClientCommand) executeErr(ctx context.Context) error {
	// Client generates an AK and sends it to the server

	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		return fmt.Errorf("while opening TPM: %w", err)
	}

	eks, err := tpm.EKs()
	if err != nil {
		return fmt.Errorf("while getting endorsement keys: %w", err)
	}

	if len(eks) == 0 {
		return fmt.Errorf("found no endorsement keys")
	}

	log.Printf("Picking endorsement key #0 (of %d)", len(eks))
	ek := eks[0]
	ekPKIX, err := x509.MarshalPKIXPublicKey(ek.Public)
	if err != nil {
		return fmt.Errorf("while marshaling endorsement key to PKIX: %w", err)
	}

	// This makes an attestation key.

	ak, err := tpm.NewAK(&attest.AKConfig{})
	if err != nil {
		return fmt.Errorf("while generating new attestation config: %w", err)
	}

	// We need to save the attestation key.  It's not actually stored in the
	// TPM.  Instead, the TPM hands us back the public key and a sealed blob
	// that contains the private key.  The only way to access the private key is
	// by loading the blob back into the TPM and using it for signing
	// operations.

	// When we marshal it, we get a JSON blob that can be loaded back into the
	// TPM to perform operations with the attestation key.  The JSON blob is
	// specific to this library.  It wraps up all the data needed for a TPM_Load
	// command, primarily the public key and the encrypted private key.

	akBytes, err := ak.Marshal()
	if err != nil {
		return fmt.Errorf("while marshaling attestation key to TPM-loadable format: %w", err)
	}

	if err := os.WriteFile(c.attestationKeyFile, akBytes, 0640); err != nil {
		return fmt.Errorf("while writing sealed attestation key to file: %w", err)
	}

	// Set up a connection to the server.
	conn, err := grpc.NewClient(c.caAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("while dialing CA: %w", err)
	}

	caClient := tpmcapb.NewCertificateAuthorityClient(conn)

	attestParams := ak.AttestationParameters()

	exchangeReq := &tpmcapb.ExchangeEKForCertRequest{
		EndorsementPublicKey:            ekPKIX,
		AttestationPublicKey:            attestParams.Public,
		AttestationKeyCreateData:        attestParams.CreateData,
		AttestationKeyCreateAttestation: attestParams.CreateAttestation,
		AttestationKeyCreateSignature:   attestParams.CreateSignature,
	}
	switch tpm.Version() {
	case attest.TPMVersion12:
		exchangeReq.TpmVersion = tpmcapb.TPMVersion_V1_2
	case attest.TPMVersion20:
		exchangeReq.TpmVersion = tpmcapb.TPMVersion_V2_0
	default:
		return fmt.Errorf("unknown TPM Version")
	}

	exchangeResp, err := caClient.ExchangeEKForCert(ctx, exchangeReq)
	if err != nil {
		return fmt.Errorf("while submitting EK to the CA: %w", err)
	}

	// The CA either rejected our request, or sent us back a certificate for the
	// attestation key, but sealed with the endorsement public key.  We need to
	// use the TPM to unseal the certificate.

	unsealedSealingKey, err := ak.ActivateCredential(tpm, attest.EncryptedCredential{
		Credential: exchangeResp.Credential,
		Secret:     exchangeResp.SealedUnsealingKey,
	})
	if err != nil {
		return fmt.Errorf("while unsealing secret: %w", err)
	}

	sealedCertPlaintext, err := unseal(exchangeResp.GetSealedCertificate(), unsealedSealingKey, exchangeResp.GetSealedCertificateNonce())
	if err != nil {
		return fmt.Errorf("while unsealing issued certificate: %w", err)
	}

	sealedCert := &tpmcapb.SealedCertificate{}
	if err := proto.Unmarshal(sealedCertPlaintext, sealedCert); err != nil {
		return fmt.Errorf("while parsing sealed certificate data: %w", err)
	}

	for i, cert := range sealedCert.GetCertificateChain() {
		pem := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		})

		log.Printf("Certificate %d:\n%s", i, pem)
	}

	return nil
}

func unseal(ciphertext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("while creating AES cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("while creating AEAD: %w", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("while unsealing plaintext: %w", err)
	}

	return plaintext, nil
}
