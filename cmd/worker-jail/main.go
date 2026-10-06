// Command worker-jail is the CLI of the worker-jail protocol (docs/protocol.md) v2.1 part A: policy, worktree seeding
// and the egress service for network mode modules.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
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
  provision   --project P --worker W --repo PATH [--ref REF]
  provision   --project P --worker W --from-worktree DIR [--allow-secret-path PATH ...] [--max-untracked-mib N]
  run         --project P --worker W [--timeout D] [--max-output B] -- ARGV...   (defaults and maximums: the policy's)
  export      --project P --worker W [-o FILE]
  apply       --repo PATH [--write-scope P1,P2,...] [--policy P.W] [--allow-review-required]
              [--allow-dirty [--snapshot-tree OID]] PATCH
  deprovision --project P --worker W [--force]
  seed-cache  --project P --name NAME   (tar on stdin)
  seed-gomod  --project P --repo PATH [--ref REF]
  seed-gomod  --project P --from-worktree DIR [--allow-secret-path PATH ...] [--max-untracked-mib N]
  usage       --project P --worker W
  ls          [--project P]
  kill        [--project P] [--worker W]
  purge       --project P
  policy check FILE [--json] [--max-risk LOW|MEDIUM|HIGH|CRITICAL]
  policy set --project P --worker W [--accept-risk CRITICAL] FILE
  policy show P W [--json]
  policy template reviewer|developer|yolo-offline --project P --worker W [--write-scope P1,P2,...] [--go-modules MASK ...]
  policy rm P W
  egress up | down | status
  egress log [--project P] [--worker W] [--since D]

policy exit codes: 0 ok, 1 invalid policy, 2 usage, 3 not found, 4 risk above --max-risk or not accepted,
5 egress unavailable: the generic modes (allowlist, denylist, all) arrive in a later v2.1 part, or the egress
service did not confirm a modules policy (also from provision and run).
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
		return report(stderr, cmdApply(ctx, cfg, rest, stdout, stderr))
	}
	if cmd == "policy" {
		return reportPolicy(stderr, cmdPolicy(ctx, cfg, rest, stdout, stderr))
	}
	j, err := jail.New(cfg)
	if err != nil {
		return report(stderr, err)
	}
	c := &cli{j: j, stdin: stdin, stdout: stdout, stderr: stderr}
	f, ok := map[string]func(context.Context, []string) (int, error){
		"doctor": c.doctor, "provision": c.provision, "run": c.run, "export": c.export,
		"deprovision": c.deprovision, "seed-cache": c.seedCache, "seed-gomod": c.seedGoMod,
		"usage": c.usage, "ls": c.ls, "kill": c.kill, "purge": c.purge, "egress": c.egress,
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
	case errors.Is(err, jail.ErrEgressUnavailable):
		fmt.Fprintf(stderr, "worker-jail: %v\n", err)
		return 5
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
	return f.require(need...)
}

// parseMixed parses flags that may follow positional arguments and returns the positionals.
func (f *flags) parseMixed(args []string, need ...string) ([]string, error) {
	var pos []string
	for {
		if err := f.Parse(args); err != nil {
			return nil, usageError{err.Error()}
		}
		if args = f.Args(); len(args) == 0 {
			break
		}
		pos, args = append(pos, args[0]), args[1:]
	}
	return pos, f.require(need...)
}

func (f *flags) require(need ...string) error {
	for _, n := range need {
		if fl := f.Lookup(n); fl == nil || fl.Value.String() == "" {
			return usageError{"--" + n + " is required"}
		}
	}
	return nil
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

// withSnapshot adds the worktree-snapshot flags of provision and seed-gomod.
func (f *flags) withSnapshot(o *jail.SnapshotOptions) *string {
	dir := f.String("from-worktree", "", "snapshot this worktree, dirty and untracked files included (excludes --repo and --ref)")
	f.Func("allow-secret-path", "exact repository path the secret guard's name rule lets through; repeatable (refused at HIGH and above)", func(v string) error {
		o.AllowSecretPaths = append(o.AllowSecretPaths, v)
		return nil
	})
	f.IntVar(&o.MaxUntrackedMiB, "max-untracked-mib", 0, "total untracked bytes a snapshot may hold, in MiB (0: 256)")
	return dir
}

// source checks that exactly one of --repo and --from-worktree is given, and the flags that go with it.
func (f *flags) source(fromWorktree string, o jail.SnapshotOptions) error {
	set := map[string]bool{}
	f.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	switch {
	case fromWorktree == "" && !set["repo"]:
		return usageError{"--repo or --from-worktree is required"}
	case fromWorktree != "" && (set["repo"] || set["ref"]):
		return usageError{"--from-worktree excludes --repo and --ref"}
	case fromWorktree == "" && (len(o.AllowSecretPaths) > 0 || o.MaxUntrackedMiB != 0):
		return usageError{"--allow-secret-path and --max-untracked-mib need --from-worktree"}
	case o.MaxUntrackedMiB < 0:
		return usageError{"--max-untracked-mib must not be negative"}
	}
	return nil
}

func (c *cli) provision(ctx context.Context, args []string) (int, error) {
	f := newFlags("provision", c.stderr).withRef()
	repo, ref := f.String("repo", "", "repository path"), f.String("ref", "", "branch, tag or HEAD (default HEAD)")
	var o jail.SnapshotOptions
	dir := f.withSnapshot(&o)
	if err := f.parse(args, "project", "worker"); err != nil {
		return 0, err
	}
	if err := f.source(*dir, o); err != nil {
		return 0, err
	}
	ws, err := c.j.Provision(ctx, jail.ProvisionSpec{Ref: f.ref(), Repo: *repo, RefName: *ref, FromWorktree: *dir, SnapshotOptions: o})
	if err != nil {
		return 0, err
	}
	fmt.Fprintf(c.stdout, "%s base=%s existed=%v", ws.Volume, ws.Base, ws.Existed)
	if ws.SnapshotTree != "" {
		fmt.Fprintf(c.stdout, " snapshot-tree=%s snapshot-parent=%s", ws.SnapshotTree, ws.SnapshotParent)
	}
	fmt.Fprintln(c.stdout)
	return 0, nil
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func (c *cli) run(ctx context.Context, args []string) (int, error) {
	f := newFlags("run", c.stderr).withRef()
	timeout := f.Duration("timeout", 0, "call timeout (0: the policy's call_timeout_s, which is also the maximum)")
	maxOut := f.Int("max-output", 0, "stdout/stderr cap in bytes (0: the policy's max_output_bytes, also the maximum)")
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
		fmt.Fprintf(c.stderr, "worker-jail: output exceeded %s; call killed\n", orPolicy(*maxOut != 0, fmt.Sprintf("%d bytes", *maxOut), "max_output_bytes"))
	}
	if res.TimedOut {
		fmt.Fprintf(c.stderr, "worker-jail: timed out after %s\n", orPolicy(*timeout != 0, timeout.String(), "call_timeout_s"))
		return 124, nil
	}
	return res.Exit, nil
}

func orPolicy(set bool, value, field string) string {
	if set {
		return value
	}
	return "the policy's " + field
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

func cmdApply(ctx context.Context, cfg jail.Config, args []string, stdout, stderr io.Writer) error {
	f := newFlags("apply", stderr)
	repo := f.String("repo", "", "clean target worktree (with --allow-dirty: a linked worktree, dirty or not)")
	policy := f.String("policy", "", "PROJECT.WORKER whose stored policy's write_scope also bounds the patch")
	allow := f.Bool("allow-review-required", false, "apply flagged paths after reading every flagged hunk")
	dirty := f.Bool("allow-dirty", false, "apply into a dirty linked worktree, working tree only (never the index, HEAD or refs)")
	snapTree := f.String("snapshot-tree", "", "with --allow-dirty: the snapshot tree the patch was made against; reports divergence")
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
	if *snapTree != "" && !*dirty {
		return usageError{"--snapshot-tree needs --allow-dirty"}
	}
	opts := jail.ApplyOptions{AllowReviewRequired: *allow, WriteScope: scope, AllowDirty: *dirty, SnapshotTree: *snapTree}
	if *policy != "" || *snapTree != "" {
		j, err := jail.New(cfg)
		if err != nil {
			return err
		}
		if *snapTree != "" {
			opts.SnapshotObjects = j.SnapshotStore()
		}
		if *policy != "" {
			project, worker, ok := strings.Cut(*policy, ".")
			if !ok {
				return usageError{"--policy takes PROJECT.WORKER"}
			}
			pol, err := j.LoadPolicy(jail.Ref{Project: project, Worker: worker})
			if err != nil {
				return err
			}
			opts.PolicyScope = &pol.Workspace.WriteScope
		}
	}
	p, err := os.Open(f.Arg(0))
	if err != nil {
		return err
	}
	defer p.Close()
	rep, err := jail.Apply(ctx, *repo, p, opts)
	switch {
	case rep.TargetTreeErr != nil:
		fmt.Fprintf(stderr, "target snapshot unavailable: %v\n", rep.TargetTreeErr)
	case rep.TargetTree != "" && rep.TargetTree != *snapTree && rep.Diverged >= 0:
		fmt.Fprintf(stderr, "target diverged since snapshot: %d paths\n", rep.Diverged)
	case rep.TargetTree != "" && rep.TargetTree != *snapTree:
		fmt.Fprintf(stderr, "target diverged since snapshot: unknown number of paths (snapshot tree %s not found)\n", *snapTree)
	}
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
	var o jail.SnapshotOptions
	dir := f.withSnapshot(&o)
	if err := f.parse(args, "project"); err != nil {
		return 0, err
	}
	if err := f.source(*dir, o); err != nil {
		return 0, err
	}
	if *dir == "" {
		return 0, c.j.SeedGoMod(ctx, *project, *repo, *ref)
	}
	tree, err := c.j.SeedGoModWorktree(ctx, *project, *dir, o)
	if err == nil {
		fmt.Fprintf(c.stdout, "%s snapshot-tree=%s\n", jail.CacheVolume(*project, "gomod"), tree)
	}
	return 0, err
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
	fmt.Fprintln(tw, "KIND\tNAME\tPROJECT\tWORKER/CACHE\tBASE/STATUS\tSNAPSHOT-TREE\tSNAPSHOT-PARENT\tCREATED")
	ts := func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.Format(time.RFC3339)
	}
	dash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	for _, w := range l.Workspaces {
		fmt.Fprintf(tw, "workspace\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", w.Volume, w.Project, w.Worker, w.Base,
			dash(w.SnapshotTree), dash(w.SnapshotParent), ts(w.Created))
	}
	for _, ca := range l.Caches {
		fmt.Fprintf(tw, "cache\t%s\t%s\t%s\t-\t%s\t-\t%s\n", ca.Volume, ca.Project, ca.Name, dash(ca.SnapshotTree), ts(ca.Created))
	}
	for _, cl := range l.Calls {
		fmt.Fprintf(tw, "call\t%s\t%s\t%s\t%s\t-\t-\t-\n", cl.ID, cl.Project, cl.Worker, strings.ReplaceAll(cl.Status, "\t", " "))
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

// egress operates the egress service (v2.1 part A): up, down, status, log.
func (c *cli) egress(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 {
		return 0, usageError{"egress needs up, down, status or log"}
	}
	f := newFlags("egress "+args[0], c.stderr)
	switch args[0] {
	case "up", "down", "status":
		if err := f.parse(args[1:]); err != nil {
			return 0, err
		}
		if f.NArg() != 0 {
			return 0, usageError{"egress " + args[0] + " takes no arguments"}
		}
	case "log":
	default:
		return 0, usageError{fmt.Sprintf("unknown egress command %q", args[0])}
	}
	switch args[0] {
	case "up":
		if err := c.j.EgressUp(ctx); err != nil {
			return 0, err
		}
		fmt.Fprintf(c.stdout, "%s up\n", jail.EgressContainer)
		return 0, nil
	case "down":
		return 0, c.j.EgressDown(ctx)
	case "status":
		rep, err := c.j.EgressStatus(ctx)
		if err != nil {
			return 0, err
		}
		state := rep.State
		if state == "" {
			state = "absent"
		}
		fmt.Fprintf(c.stdout, "%s %s\n", jail.EgressContainer, state)
		code := 0
		if rep.State != "running" {
			code = 5
		}
		for _, w := range rep.Workers {
			st := "ok"
			switch {
			case w.Mode != jail.NetModules:
				st, code = "not served (the generic modes arrive in a later v2.1 part)", 5
			case w.Loaded == "":
				st, code = "NOT LOADED", 5
			case w.Loaded != w.Stored:
				st, code = "STALE (loaded "+w.Loaded+")", 5
			}
			fmt.Fprintf(c.stdout, "%s.%s %s stored=%s %s\n", w.Project, w.Worker, w.Mode, w.Stored, st)
		}
		return code, nil
	}
	var lf jail.EgressLogFilter
	f.StringVar(&lf.Project, "project", "", "only this project's lines")
	f.StringVar(&lf.Worker, "worker", "", "only this worker's lines")
	f.StringVar(&lf.Since, "since", "", "docker logs --since (a duration such as 1h, or a timestamp)")
	if err := f.parse(args[1:]); err != nil {
		return 0, err
	}
	if f.NArg() != 0 {
		return 0, usageError{"egress log takes only flags"}
	}
	return 0, c.j.EgressLog(ctx, lf, c.stdout)
}

// reportPolicy maps the policy commands' errors to their exit codes; the rest are as for every command.
func reportPolicy(stderr io.Writer, err error) int {
	switch {
	case errors.Is(err, jail.ErrPolicyInvalid):
		fmt.Fprintf(stderr, "worker-jail: %v\n", err)
		return 1
	case errors.Is(err, jail.ErrRiskExceeded):
		fmt.Fprintf(stderr, "worker-jail: %v\n", err)
		return 4
	}
	return report(stderr, err)
}

func cmdPolicy(ctx context.Context, cfg jail.Config, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError{"policy needs check, set, show, template or rm"}
	}
	switch args[0] {
	case "check":
		return policyCheck(args[1:], stdout, stderr)
	case "template":
		return policyTemplate(args[1:], stdout, stderr)
	case "set", "show", "rm":
	default:
		return usageError{fmt.Sprintf("unknown policy command %q", args[0])}
	}
	j, err := jail.New(cfg)
	if err != nil {
		return err
	}
	switch args[0] {
	case "set":
		return policySet(ctx, j, args[1:], stdout, stderr)
	case "show":
		return policyShow(j, args[1:], stdout, stderr)
	}
	f := newFlags("policy rm", stderr)
	pos, err := f.parseMixed(args[1:])
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return usageError{"policy rm needs P W"}
	}
	return j.RemovePolicy(jail.Ref{Project: pos[0], Worker: pos[1]})
}

// readPolicyFile reads at most one byte more than a policy may hold, so the size check still fires.
func readPolicyFile(path string) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return io.ReadAll(io.LimitReader(fh, jail.PolicyMaxBytes+1))
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func policyCheck(args []string, stdout, stderr io.Writer) error {
	f := newFlags("policy check", stderr)
	asJSON := f.Bool("json", false, "print {level, reasons, warnings, policy_id}")
	maxRisk := f.String("max-risk", "", "exit 4 when the level is above LOW, MEDIUM, HIGH or CRITICAL")
	pos, err := f.parseMixed(args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError{"policy check needs exactly one FILE"}
	}
	var limit jail.Risk
	if *maxRisk != "" {
		if limit, err = jail.ParseRisk(*maxRisk); err != nil {
			return usageError{err.Error()}
		}
	}
	data, err := readPolicyFile(pos[0])
	if err != nil {
		return err
	}
	p, err := jail.ParsePolicy(data)
	if err != nil {
		return err
	}
	r := jail.EffectiveRisk(p)
	if *asJSON {
		err = writeJSON(stdout, r)
	} else {
		_, err = io.WriteString(stdout, jail.FormatPolicyCheck(p, r))
	}
	if err != nil {
		return err
	}
	if limit != 0 && r.Level > limit {
		return fmt.Errorf("%w: %s is above --max-risk %s", jail.ErrRiskExceeded, r.Level, limit)
	}
	return nil
}

func policySet(ctx context.Context, j *jail.Jail, args []string, stdout, stderr io.Writer) error {
	f := newFlags("policy set", stderr).withRef()
	accept := f.String("accept-risk", "", "CRITICAL: store a CRITICAL policy")
	pos, err := f.parseMixed(args, "project", "worker")
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError{"policy set needs exactly one FILE"}
	}
	var o jail.SetPolicyOptions
	switch *accept {
	case "":
	case "CRITICAL":
		o.AcceptRisk = jail.RiskCritical
	default:
		return usageError{"--accept-risk takes only CRITICAL"}
	}
	data, err := readPolicyFile(pos[0])
	if err != nil {
		return err
	}
	sp, err := j.SetPolicy(ctx, f.ref(), data, o)
	if sp.EgressWarning != "" {
		fmt.Fprintf(stderr, "warning: %s\n", sp.EgressWarning)
	}
	if err != nil {
		return err
	}
	for _, w := range sp.Risk.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}
	fmt.Fprintf(stdout, "%s.%s id=%s risk=%s", sp.Policy.Project, sp.Policy.Worker, sp.Policy.ID(), sp.Risk.Level)
	if sp.Policy.Network.Mode == jail.NetModules {
		fmt.Fprint(stdout, " egress=confirmed")
	}
	fmt.Fprintln(stdout)
	return nil
}

func policyShow(j *jail.Jail, args []string, stdout, stderr io.Writer) error {
	f := newFlags("policy show", stderr)
	asJSON := f.Bool("json", false, "print the stored policy, its id and its risk as JSON")
	pos, err := f.parseMixed(args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return usageError{"policy show needs P W"}
	}
	sp, err := j.ShowPolicy(jail.Ref{Project: pos[0], Worker: pos[1]})
	if err != nil {
		return err
	}
	if *asJSON {
		canon, err := jail.CanonicalPolicy(sp.Raw)
		if err != nil {
			return err
		}
		return writeJSON(stdout, struct {
			Path   string          `json:"path"`
			Policy json.RawMessage `json:"policy"`
			jail.RiskReport
		}{sp.Path, canon, sp.Risk})
	}
	fmt.Fprint(stdout, jail.FormatPolicyCheck(sp.Policy, sp.Risk))
	fmt.Fprintf(stdout, "%-10s %s\n", "stored", sp.Path)
	stdout.Write(sp.Raw)
	if len(sp.Raw) > 0 && sp.Raw[len(sp.Raw)-1] != '\n' {
		fmt.Fprintln(stdout)
	}
	return nil
}

func policyTemplate(args []string, stdout, stderr io.Writer) error {
	f := newFlags("policy template", stderr).withRef()
	var scope, modules []string
	f.Func("write-scope", "comma-separated path prefixes apply accepts (developer); repeatable", func(v string) error {
		scope = append(scope, strings.Split(v, ",")...)
		return nil
	})
	f.Func("go-modules", "one module mask per flag (developer); repeatable", func(v string) error {
		modules = append(modules, v)
		return nil
	})
	pos, err := f.parseMixed(args, "project", "worker")
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError{"policy template needs exactly one NAME (" + strings.Join(jail.Templates, ", ") + ")"}
	}
	switch {
	case !slices.Contains(jail.Templates, pos[0]):
		return usageError{fmt.Sprintf("unknown template %q (%s)", pos[0], strings.Join(jail.Templates, ", "))}
	case pos[0] == "developer" && (len(scope) == 0 || len(modules) == 0):
		return usageError{"template developer needs --write-scope and --go-modules"}
	case pos[0] != "developer" && (len(scope) > 0 || len(modules) > 0):
		return usageError{"template " + pos[0] + " takes no --write-scope or --go-modules"}
	}
	data, err := jail.PolicyTemplate(jail.TemplateSpec{Name: pos[0], Project: *f.project, Worker: *f.worker,
		WriteScope: scope, GoModules: modules})
	if err != nil {
		return err
	}
	_, err = stdout.Write(data)
	return err
}
