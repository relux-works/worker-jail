// Command rwp-egress is the egress service of remote-workplace v2.1 (docs/design/v2/egress.md): the modules mode and the
// generic modes (allowlist, denylist, all). It runs as the container rwp-egress in the workers VM, started by
// `remote-workplace egress up`.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/relux-works/remote-workplace/egress"
)

// Directories inside the service container (the volumes rwp-egress-sock, rwp-egress-policy and rwp-egress-cache).
const (
	defaultSockRoot  = "/egress/sock"
	defaultPolicyDir = "/egress/policy"
	defaultCacheDir  = "/egress/cache"
)

const usage = `usage:
  rwp-egress serve [--sockroot DIR] [--policydir DIR] [--cachedir DIR]
  rwp-egress status [--cachedir DIR] P.W     prints the loaded policy id, or none (exit 3)
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet("rwp-egress "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	cache := fs.String("cachedir", defaultCacheDir, "cache namespaces and the control socket")
	switch args[0] {
	case "serve":
		sock := fs.String("sockroot", defaultSockRoot, "one <P>.<W>/egress.sock per served worker")
		pol := fs.String("policydir", defaultPolicyDir, "policy files <P>.<W>.json (read-only)")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		svc, err := egress.New(egress.Config{SockRoot: *sock, PolicyDir: *pol, CacheDir: *cache, Log: os.Stdout})
		if err != nil {
			fmt.Fprintf(stderr, "rwp-egress: %v\n", err)
			return 1
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		if err := svc.Serve(ctx, hup); err != nil {
			fmt.Fprintf(stderr, "rwp-egress: %v\n", err)
			return 1
		}
		return 0
	case "status":
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 1 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		id, err := egress.Status(*cache, fs.Arg(0))
		switch {
		case errors.Is(err, egress.ErrNotLoaded):
			fmt.Fprintln(stdout, "none")
			return 3
		case err != nil:
			fmt.Fprintf(stderr, "rwp-egress: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, id)
		return 0
	}
	fmt.Fprint(stderr, usage)
	return 2
}
