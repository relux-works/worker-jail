// Command worker-jail is the CLI of the worker-jail protocol v1 (docs/protocol.md).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/relux-works/worker-jail/jail"
)

const usage = `usage: worker-jail [--image IMG] [--state-dir DIR] [--slots N] [--project-slots M] COMMAND [flags]

commands:
  doctor
  provision   --project P --worker W --repo PATH [--ref REF | --from-worktree]
  run         --project P --worker W [--timeout 10m] [--max-output 4194304] -- ARGV...
  export      --project P --worker W [-o FILE]
  apply       --repo PATH [--write-scope P1,P2,...] [--allow-dirty] [--allow-review-required] PATCH
  deprovision --project P --worker W [--force]
  seed-cache  --project P --name NAME   (tar on stdin)
  seed-gomod  --project P --repo PATH [--ref REF | --from-worktree]
  usage       --project P --worker W
  ls          [--project P]
  kill        [--project P] [--worker W]
  purge       --project P
`

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func envInt(name string) int {
	n, _ := strconv.Atoi(os.Getenv(name))
	return n
}

func run(ctx context.Context, args []string, stdin *os.File, stdout, stderr io.Writer) int {
	g := flag.NewFlagSet("worker-jail", flag.ContinueOnError)
	g.SetOutput(stderr)
	g.Usage = func() { fmt.Fprint(stderr, usage) }
	var cfg jail.Config
	g.StringVar(&cfg.Image, "image", os.Getenv("WJ_IMAGE"), "container image")
	g.StringVar(&cfg.StateDir, "state-dir", os.Getenv("WJ_STATE_DIR"), "host state directory")
	g.IntVar(&cfg.Slots, "slots", envInt("WJ_SLOTS"), "global call slots (0: VM CPUs)")
	g.IntVar(&cfg.ProjectSlots, "project-slots", envInt("WJ_PROJECT_SLOTS"), "per-project call slots (0: half)")
	if err := g.Parse(args); err != nil {
		return 2
	}
	if g.NArg() == 0 {
		g.Usage()
		return 2
	}
	cmd, rest := g.Arg(0), g.Args()[1:]
	if cmd == "apply" {
		return report(stderr, cmdApply(ctx, rest, stdout, stderr))
	}
	j, err := jail.New(cfg)
	if err != nil {
		return report(stderr, err)
	}
	c := &cli{j: j, stdin: stdin, stdout: stdout, stderr: stderr}
	f, ok := map[string]func(context.Context, []string) (int, error){
		"doctor": c.doctor, "provision": c.provision, "run": c.run, "export": c.export,
		"deprovision": c.deprovision, "seed-cache": c.seedCache, "seed-gomod": c.seedGoMod,
		"usage": c.usage, "ls": c.ls, "kill": c.kill, "purge": c.purge,
	}[cmd]
	if !ok {
		fmt.Fprintf(stderr, "worker-jail: unknown command %q\n", cmd)
		g.Usage()
		return 2
	}
	code, err := f(ctx, rest)
	if err != nil {
		return report(stderr, err)
	}
	return code
}

func report(stderr io.Writer, err error) int {
	var ue usageError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ue):
		fmt.Fprintf(stderr, "worker-jail: %s\n", ue.msg)
		return 2
	case errors.Is(err, flag.ErrHelp):
		return 2
	case errors.Is(err, jail.ErrOutOfScope):
		fmt.Fprintf(stderr, "worker-jail: %v\n", err)
		return 5
	case errors.Is(err, jail.ErrReviewRequired):
		fmt.Fprintf(stderr, "worker-jail: %v\n", err)
		return 4
	default:
		fmt.Fprintf(stderr, "worker-jail: %v\n", err)
		return 3
	}
}

type cli struct {
	j              *jail.Jail
	stdin          *os.File
	stdout, stderr io.Writer
}

type flags struct {
	*flag.FlagSet
	project, worker *string
}

func newFlags(name string, stderr io.Writer) *flags {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return &flags{FlagSet: fs}
}

func (f *flags) withRef() *flags {
	f.project = f.String("project", "", "project name")
	f.worker = f.String("worker", "", "worker name")
	return f
}

func (f *flags) parse(args []string, need ...string) error {
	if err := f.Parse(args); err != nil {
		return usageError{err.Error()}
	}
	for _, n := range need {
		if fl := f.Lookup(n); fl == nil || fl.Value.String() == "" {
			return usageError{"--" + n + " is required"}
		}
	}
	return nil
}

func (f *flags) isSet(name string) (set bool) {
	f.Visit(func(fl *flag.Flag) { set = set || fl.Name == name })
	return set
}

func (f *flags) ref() jail.Ref { return jail.Ref{Project: *f.project, Worker: *f.worker} }

func (c *cli) doctor(ctx context.Context, args []string) (int, error) {
	f := newFlags("doctor", c.stderr)
	if err := f.parse(args); err != nil {
		return 0, err
	}
	rep, err := c.j.Doctor(ctx)
	for _, ch := range rep.Checks {
		st := "ok"
		if !ch.OK {
			st = "FAIL"
		}
		fmt.Fprintf(c.stdout, "%-4s %-9s %s\n", st, ch.Name, ch.Detail)
	}
	return 0, err
}

func (c *cli) provision(ctx context.Context, args []string) (int, error) {
	f := newFlags("provision", c.stderr).withRef()
	repo, ref := f.String("repo", "", "repository path"), f.String("ref", "HEAD", "branch, tag or HEAD")
	wt := f.Bool("from-worktree", false, "snapshot the repository's working tree as base")
	if err := f.parse(args, "project", "worker", "repo"); err != nil {
		return 0, err
	}
	spec := jail.ProvisionSpec{Ref: f.ref(), Repo: *repo, RefName: *ref, FromWorktree: *wt}
	if *wt {
		if f.isSet("ref") {
			return 0, usageError{"--from-worktree and --ref are mutually exclusive"}
		}
		spec.RefName = ""
	}
	ws, err := c.j.Provision(ctx, spec)
	if err != nil {
		return 0, err
	}
	if *wt {
		fmt.Fprintf(c.stdout, "%s base=%s existed=%v source=worktree\n", ws.Volume, ws.Base, ws.Existed)
	} else {
		fmt.Fprintf(c.stdout, "%s base=%s existed=%v\n", ws.Volume, ws.Base, ws.Existed)
	}
	return 0, nil
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func (c *cli) run(ctx context.Context, args []string) (int, error) {
	f := newFlags("run", c.stderr).withRef()
	timeout := f.Duration("timeout", jail.DefaultTimeout, "call timeout (max 60m)")
	maxOut := f.Int("max-output", jail.DefaultMaxOutput, "stdout/stderr cap in bytes")
	if err := f.parse(args, "project", "worker"); err != nil {
		return 0, err
	}
	if f.NArg() == 0 {
		return 0, usageError{"run needs ARGV after --"}
	}
	var in io.Reader
	if c.stdin != nil && !isTerminal(c.stdin) {
		in = c.stdin
	}
	res, err := c.j.Run(ctx, f.ref(), jail.RunSpec{Argv: f.Args(), Stdin: in, Timeout: *timeout, MaxOutput: *maxOut})
	c.stdout.Write(res.Stdout)
	c.stderr.Write(res.Stderr)
	if err != nil {
		return 0, err
	}
	if res.Truncated {
		fmt.Fprintf(c.stderr, "worker-jail: output exceeded %d bytes; call killed\n", *maxOut)
	}
	if res.TimedOut {
		fmt.Fprintf(c.stderr, "worker-jail: timed out after %v\n", *timeout)
		return 124, nil
	}
	return res.Exit, nil
}

func (c *cli) export(ctx context.Context, args []string) (int, error) {
	f := newFlags("export", c.stderr).withRef()
	out := f.String("o", "", "output file (default stdout)")
	if err := f.parse(args, "project", "worker"); err != nil {
		return 0, err
	}
	if *out == "" {
		_, err := c.j.Export(ctx, f.ref(), c.stdout)
		return 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(*out), ".wj-export-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	info, err := c.j.Export(ctx, f.ref(), tmp)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, err
	}
	if err := os.Rename(tmp.Name(), *out); err != nil {
		return 0, err
	}
	fmt.Fprintf(c.stderr, "%s bytes=%d sha256=%s base=%s\n", *out, info.Bytes, info.SHA256, info.Base)
	return 0, nil
}

func cmdApply(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	f := newFlags("apply", stderr)
	repo := f.String("repo", "", "target worktree (clean unless --allow-dirty)")
	allow := f.Bool("allow-review-required", false, "apply flagged paths after reading every flagged hunk")
	dirty := f.Bool("allow-dirty", false, "apply to a dirty worktree's working tree only (never its index)")
	var scope []string
	f.Func("write-scope", "comma-separated path prefixes the patch may touch (dir/ or file); repeatable", func(v string) error {
		scope = append(scope, strings.Split(v, ",")...)
		return nil
	})
	if err := f.parse(args, "repo"); err != nil {
		return err
	}
	if f.NArg() != 1 {
		return usageError{"apply needs exactly one PATCH file"}
	}
	p, err := os.Open(f.Arg(0))
	if err != nil {
		return err
	}
	defer p.Close()
	rep, err := jail.Apply(ctx, *repo, p, jail.ApplyOptions{AllowReviewRequired: *allow, WriteScope: scope, AllowDirty: *dirty})
	for _, pth := range rep.OutOfScope {
		fmt.Fprintf(stderr, "out of scope: %s\n", pth)
	}
	for _, fl := range rep.Flagged {
		fmt.Fprintf(stderr, "flagged: %s (%s)\n", fl.Path, fl.Reason)
	}
	if err == nil {
		for _, pth := range rep.Paths {
			fmt.Fprintln(stdout, pth)
		}
	}
	return err
}

func (c *cli) deprovision(ctx context.Context, args []string) (int, error) {
	f := newFlags("deprovision", c.stderr).withRef()
	force := f.Bool("force", false, "discard unexported changes")
	if err := f.parse(args, "project", "worker"); err != nil {
		return 0, err
	}
	return 0, c.j.Deprovision(ctx, f.ref(), *force)
}

func (c *cli) seedCache(ctx context.Context, args []string) (int, error) {
	f := newFlags("seed-cache", c.stderr)
	project, name := f.String("project", "", "project"), f.String("name", "", "cache name")
	if err := f.parse(args, "project", "name"); err != nil {
		return 0, err
	}
	if c.stdin == nil || isTerminal(c.stdin) {
		return 0, usageError{"seed-cache reads a tar on stdin"}
	}
	return 0, c.j.SeedCache(ctx, *project, *name, c.stdin)
}

func (c *cli) seedGoMod(ctx context.Context, args []string) (int, error) {
	f := newFlags("seed-gomod", c.stderr)
	project := f.String("project", "", "project")
	repo, ref := f.String("repo", "", "repository path"), f.String("ref", "HEAD", "revision")
	wt := f.Bool("from-worktree", false, "use a snapshot of the repository's working tree")
	if err := f.parse(args, "project", "repo"); err != nil {
		return 0, err
	}
	if *wt {
		if f.isSet("ref") {
			return 0, usageError{"--from-worktree and --ref are mutually exclusive"}
		}
		return 0, c.j.SeedGoModWorktree(ctx, *project, *repo)
	}
	return 0, c.j.SeedGoMod(ctx, *project, *repo, *ref)
}

func (c *cli) usage(ctx context.Context, args []string) (int, error) {
	f := newFlags("usage", c.stderr).withRef()
	if err := f.parse(args, "project", "worker"); err != nil {
		return 0, err
	}
	n, err := c.j.Usage(ctx, f.ref())
	if err == nil {
		fmt.Fprintln(c.stdout, n)
	}
	return 0, err
}

func (c *cli) ls(ctx context.Context, args []string) (int, error) {
	f := newFlags("ls", c.stderr)
	project := f.String("project", "", "project (default all)")
	if err := f.parse(args); err != nil {
		return 0, err
	}
	l, err := c.j.List(ctx, *project)
	if err != nil {
		return 0, err
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "KIND\tNAME\tPROJECT\tWORKER/CACHE\tBASE/STATUS\tCREATED")
	ts := func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.Format(time.RFC3339)
	}
	for _, w := range l.Workspaces {
		fmt.Fprintf(tw, "workspace\t%s\t%s\t%s\t%s\t%s\n", w.Volume, w.Project, w.Worker, w.Base, ts(w.Created))
	}
	for _, ca := range l.Caches {
		fmt.Fprintf(tw, "cache\t%s\t%s\t%s\t-\t%s\n", ca.Volume, ca.Project, ca.Name, ts(ca.Created))
	}
	for _, cl := range l.Calls {
		fmt.Fprintf(tw, "call\t%s\t%s\t%s\t%s\t-\n", cl.ID, cl.Project, cl.Worker, strings.ReplaceAll(cl.Status, "\t", " "))
	}
	return 0, tw.Flush()
}

func (c *cli) kill(ctx context.Context, args []string) (int, error) {
	f := newFlags("kill", c.stderr)
	project, worker := f.String("project", "", "project"), f.String("worker", "", "worker")
	if err := f.parse(args); err != nil {
		return 0, err
	}
	n, err := c.j.Kill(ctx, *project, *worker)
	if err == nil {
		fmt.Fprintf(c.stdout, "killed %d\n", n)
	}
	return 0, err
}

func (c *cli) purge(ctx context.Context, args []string) (int, error) {
	f := newFlags("purge", c.stderr)
	project := f.String("project", "", "project")
	if err := f.parse(args, "project"); err != nil {
		return 0, err
	}
	return 0, c.j.Purge(ctx, *project)
}
