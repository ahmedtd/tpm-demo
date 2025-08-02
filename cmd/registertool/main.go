package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/go-attestation/attest"
	"github.com/google/subcommands"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")

	subcommands.Register(&RegisterCommand{}, "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}

type RegisterCommand struct {
}

var _ subcommands.Command = (*RegisterCommand)(nil)

func (*RegisterCommand) Name() string {
	return "register"
}

func (*RegisterCommand) Synopsis() string {
	return "TODO"
}

func (*RegisterCommand) Usage() string {
	return `TODO`
}

func (c *RegisterCommand) SetFlags(f *flag.FlagSet) {
}

func (c *RegisterCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := c.executeErr(ctx); err != nil {
		log.Printf("Error: %v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *RegisterCommand) executeErr(ctx context.Context) error {
	// Client generates an AK and sends it to the server

	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		return fmt.Errorf("while opening TPM: %w", err)
	}

	tpmVersion := tpm.Version()
	if tpmVersion == attest.TPMVersion12 {
		log.Printf("TPM Version: 1.2")
	} else if tpmVersion == attest.TPMVersion20 {
		log.Printf("TPM Version: 2.0")
	} else {
		return fmt.Errorf("unknown TPM Version")
	}

	eks, err := tpm.EKs()
	if err != nil {
		return fmt.Errorf("while getting endorsement keys: %w", err)
	}
	ek := eks[0]

	// This makes an attestation key.

	ak, err := tpm.NewAK(&attest.AKConfig{})
	if err != nil {
		return fmt.Errorf("while generating new attestation config: %w", err)
	}
	attestParams := ak.AttestationParameters()

	// We need to save the attestation key.  It's not actually stored in the
	// TPM.  Instead, the TPM hands us back the public key and a sealed blob
	// that contains the private key.  The only way to access the private key is
	// by loading the blob back into the TPM and using it for signing
	// operations.

	// When we marshal it, we get an JSON blob that can be loaded back into the
	// TPM to perform operations with the attestation key.  The JSON blob is
	// specific to this library.  It wraps up all the data needed for a TPM_Load
	// command, primarily the public key and the encrypted private key.

	// if err := os.WriteFile("encrypted_aik.json", akBytes, 0600); err != nil {
	// 	// handle error
	// }

	akBytes, err := ak.Marshal()
	if err != nil {
		return fmt.Errorf("while marshaling attestation key to TPM-loadable format: %w", err)
	}

	for i, ek := range eks {
		log.Printf("Endorsement Key %d: %+v", i, ek)
	}

	log.Printf("Attestation Parameters: %+v", attestParams)
	log.Printf("Attestation Key Encrypted Bytes: %s", string(akBytes))

	// // send TPM version, EK, and attestParams to the server

	// Server validates EK and/or EK certificate

	// The activation secret is 32 random bytes

	params := attest.ActivationParameters{
		TPMVersion: tpmVersion,
		EK:         ek.Public,
		AK:         attestParams,
	}
	secret, encryptedCredentials, err := params.Generate()
	if err != nil {
		return fmt.Errorf("while generating credential activation challenge: %w", err)
	}

	log.Printf("Secret: %v", secret)
	log.Printf("Encrypted Secret: %v", encryptedCredentials)

	// return encrypted credentials to client

	// Client decrypts the credential

	// akBytes, err := os.ReadFile("encrypted_aik.json")
	// if err != nil {
	// 	// handle error
	// }
	// ak, err := tpm.LoadAK(akBytes)
	// if err != nil {
	// 	// handle error
	// }
	clientUnsealedSecret, err := ak.ActivateCredential(tpm, *encryptedCredentials)
	if err != nil {
		return fmt.Errorf("while unsealing secret: %w", err)
	}

	// return clientUnsealedSecret to server

	log.Printf("clientUnsealedSecret: %s", base64.RawURLEncoding.EncodeToString(clientUnsealedSecret))

	// Server compares clientUnsealedSecret to the secret it's holding.  If they
	// match, the client has access to use the endorsement key to decrypt
	// messages.

	return nil

}
