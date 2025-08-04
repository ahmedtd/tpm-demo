package main

import (
	"context"
	"encoding/pem"
	"flag"
	"fmt"
	"log"

	"github.com/google/go-attestation/attest"
	"github.com/google/subcommands"
)

type PrintEKCertCommand struct {
}

var _ subcommands.Command = (*PrintEKCertCommand)(nil)

func (*PrintEKCertCommand) Name() string {
	return "print-ek-cert"
}

func (*PrintEKCertCommand) Synopsis() string {
	return "TODO"
}

func (*PrintEKCertCommand) Usage() string {
	return `TODO`
}

func (c *PrintEKCertCommand) SetFlags(f *flag.FlagSet) {
}

func (c *PrintEKCertCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := c.executeErr(ctx); err != nil {
		log.Printf("Error: %v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *PrintEKCertCommand) executeErr(ctx context.Context) error {
	config := &attest.OpenConfig{}
	tpm, err := attest.OpenTPM(config)
	if err != nil {
		return fmt.Errorf("while opening TPM: %w", err)
	}

	endorsementCerts, err := tpm.EKCertificates()
	if err != nil {
		return fmt.Errorf("while getting endorsement certificates: %w", err)
	}

	log.Printf("Found %d endorsement certificates", len(endorsementCerts))

	for _, ec := range endorsementCerts {
		fmt.Println(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ec.Certificate.Raw,
		}))
	}

	return nil
}
