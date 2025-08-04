package main

import (
	"context"
	"flag"
	"os"

	"github.com/google/subcommands"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")

	subcommands.Register(&CAClientCommand{}, "")
	subcommands.Register(&CAServerCommand{}, "")
	subcommands.Register(&GenCACommand{}, "")
	subcommands.Register(&PrintEKCommand{}, "")
	subcommands.Register(&PrintEKCertCommand{}, "")
	subcommands.Register(&PrintMachineCommand{}, "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
