package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"

	"github.com/google/go-attestation/attest"
	"github.com/google/subcommands"
)

type PrintEKCommand struct {
}

var _ subcommands.Command = (*PrintEKCommand)(nil)

func (*PrintEKCommand) Name() string {
	return "print-ek"
}

func (*PrintEKCommand) Synopsis() string {
	return "TODO"
}

func (*PrintEKCommand) Usage() string {
	return `TODO`
}

func (c *PrintEKCommand) SetFlags(f *flag.FlagSet) {
}

func (c *PrintEKCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := c.executeErr(ctx); err != nil {
		log.Printf("Error: %v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *PrintEKCommand) executeErr(ctx context.Context) error {
	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		return fmt.Errorf("while opening TPM: %w", err)
	}

	eks, err := tpm.EKs()
	if err != nil {
		return fmt.Errorf("while getting endorsement keys: %w", err)
	}

	log.Printf("Found %d endorsement keys", len(eks))

	for _, ek := range eks {
		der, err := x509.MarshalPKIXPublicKey(ek.Public)
		if err != nil {
			return fmt.Errorf("while marshaling endorsement key to PKIX: %w", err)
		}

		fmt.Println(string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		})))
	}

	return nil
}
