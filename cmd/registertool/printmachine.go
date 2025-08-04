package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"log"

	"github.com/ahmedtd/tpm-demo/lib/machinedbpb"
	"github.com/google/go-attestation/attest"
	"github.com/google/subcommands"
	"google.golang.org/protobuf/encoding/prototext"
)

type PrintMachineCommand struct {
}

var _ subcommands.Command = (*PrintMachineCommand)(nil)

func (*PrintMachineCommand) Name() string {
	return "print-machine"
}

func (*PrintMachineCommand) Synopsis() string {
	return "TODO"
}

func (*PrintMachineCommand) Usage() string {
	return `TODO`
}

func (c *PrintMachineCommand) SetFlags(f *flag.FlagSet) {
}

func (c *PrintMachineCommand) Execute(ctx context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if err := c.executeErr(ctx); err != nil {
		log.Printf("Error: %v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *PrintMachineCommand) executeErr(ctx context.Context) error {
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

	log.Printf("Picking endorsment key #0 (of %d)", len(eks))
	ek := eks[0]

	ekPKIX, err := x509.MarshalPKIXPublicKey(ek.Public)
	if err != nil {
		return fmt.Errorf("while marshaling endorsement key to PKIX: %w", err)
	}

	machineDB := &machinedbpb.MachineList{
		Machines: []*machinedbpb.Machine{
			{
				EndorsementPublicKeyPkix: ekPKIX,
			},
		},
	}

	machineText, err := prototext.Marshal(machineDB)
	if err != nil {
		return fmt.Errorf("while marshaling machine to prototext: %w", err)
	}

	fmt.Println(string(machineText))

	return nil
}
