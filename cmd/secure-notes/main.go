// Command secure-notes: private notes on an attested instance.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"securenotes/internal/app"
	"securenotes/internal/volume"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		os.Exit(serve())
	case "data-volume":
		os.Exit(dataVolume())
	case "version":
		fmt.Println(app.Version)
	default:
		fmt.Fprintln(os.Stderr, "usage: secure-notes serve|data-volume|version")
		os.Exit(2)
	}
}

func serve() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	a := app.New(app.Options{Settings: app.SettingsFromEnv()})
	if err := a.Run(ctx); err != nil {
		app.Event("fatal", "error", err.Error())
		return 1
	}
	return 0
}

func dataVolume() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	logf := func(s string) { fmt.Println(s) }
	volume.RelaxPrivilegedPorts(logf)
	m := volume.New(logf)
	if _, err := m.Ensure(ctx); err != nil {
		if _, ok := err.(*volume.Refusal); !ok {
			logf("REFUSED: " + err.Error())
		}
		return 1
	}
	return 0
}
