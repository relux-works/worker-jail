# How Claude Code jails its own models: primary-source findings

Researched 2026-09-29. This is research only; no repository was changed.

## Sources
- **srt**: https://github.com/anthropic-experimental/sandbox-runtime, shallow clone at `./src`,
  commit **3ed97390547bdd3d5cec5097d123f3a5fb741c6b** (2026-09-28). Code refs below are `src/sandbox/<file>:<line>`
  in that tree; README refs are `README.md:<line>`.
- [SBX] https://code.claude.com/docs/en/sandboxing
- [SREF] https://code.claude.com/docs/en/settings-reference (raw `.md` copy in `raw/`)
- [PERM] https://code.claude.com/docs/en/permissions · [MODES] https://code.claude.com/docs/en/permission-modes
- [SET] https://code.claude.com/docs/en/settings · [MSET] https://code.claude.com/docs/en/managed-settings
- [SEC] https://code.claude.com/docs/en/security · [HOOKS] https://code.claude.com/docs/en/hooks
- [WEB] https://code.claude.com/docs/en/claude-code-on-the-web · [CENV] https://code.claude.com/docs/en/cloud-environments
- [SENV] https://code.claude.com/docs/en/sandbox-environments · [DEVC] https://code.claude.com/docs/en/devcontainer
- [ENG] https://www.anthropic.com/engineering/claude-code-sandboxing (2025-10-20). I could only read this through
  the WebFetch summarizer, so its quotes are probably verbatim but not certainly.
- Advisories: `gh api repos/{anthropic-experimental/sandbox-runtime,anthropics/claude-code}/security-advisories`.
- Detailed doc notes with verbatim quotes are in `docs-notes.md` in the research session (not committed). Where I cite a doc, the claim is from that page.

Legend: **[F]** means stated by a source. **[I]** means my inference. "not stated" means no source says it.
## 1. sandbox-runtime (srt) architecture

**Common model [F]:** both filesystem and network isolation are required, and they apply to the whole process tree
(README.md:105-135). Network access is deny-all. Egress goes only through two proxies (HTTP and SOCKS5) that run
**on the host, outside the sandbox**, and they enforce allow/deny lists (README.md:695-701). On macOS, Linux and
Windows the enforcement primitives are Seatbelt, bubblewrap and a WFP filter keyed on a dedicated account SID
(README.md:107-109). Windows is alpha.
### macOS (Seatbelt)
- [F] srt generates the profile per command and runs it via `/usr/bin/sandbox-exec` (macos-sandbox-utils.ts:1478).
  The profile starts `(version 1)` `(deny default (with message "<logTag>"))` (:969-970), then allows
  `process-exec`, `process-fork`, `process-info* (target same-sandbox)` (:976-978) and a fixed list of mach-lookup
  services (logd, fonts, opendirectoryd, securityd, launchservicesd, …; :986-1000, :1122-1123).
- [F] Reads use the order `(allow file-read*)`, then `(deny …denyRead)`, then `(allow …allowRead)`, then re-emitted
  denies for any more-specific deny under an allow (:769-819). Writes default to deny, followed by
  `(allow file-write* …allowWrite)` and then `(deny file-write* …denyWrite + mandatory denies)` (:872-905).
- [F] Network (:1143-1230). With no restriction the profile allows `(allow network*)`. With restriction it allows
  `network-bind/inbound/outbound` **only to `localhost:<httpProxyPort>` and `localhost:<socksProxyPort>`**.
  `allowLocalBinding` adds `network-bind`/`inbound` on `*:*` and `outbound (remote ip "localhost:*")`. Loopback egress
  therefore bypasses the proxy when this is on (README.md:370). Unix sockets need `system-socket AF_UNIX` and are
  allowed only for `allowUnixSockets` subpaths or with `allowAllUnixSockets`. Otherwise they are blocked.
- [F] Optional, off-by-default holes: `enableWeakerNetworkIsolation` (trustd mach service, "potential data
  exfiltration vector"), `allowAppleEvents` ("removes code-execution isolation" via `open`), and `allowMachLookup`
  (README.md:459-465, 881-893; macos-sandbox-utils.ts:1006-1028).
- [F] DNS: mDNSResponder is not in the mach-lookup allow list, and its violations are filtered as noise
  (macos-sandbox-utils.ts:1568). [I] So in-sandbox name resolution fails, and names are resolved by the host proxy.
### Linux (bubblewrap + socat + seccomp)
- [F] bwrap args include `--new-session --die-with-parent` (linux-sandbox-utils.ts:3033), `--unshare-net` whenever
  the network is restricted (:3116-3118), and `--unshare-pid` plus `--unshare-user` (:3220-3239). They also include a
  fresh `--proc /proc` unless `enableWeakerNestedSandbox` is set. In that case the host `/proc` is bind-mounted
  (:3246-3254), which "considerably weakens security" (README.md:890).
- [F] Bridging (:1158-1180, :1377-1379). On the host, socat listens on per-session **Unix sockets** and forwards to
  the host HTTP/SOCKS proxies. Those sockets are bind-mounted into the sandbox. Inside the sandbox, socat
  `TCP-LISTEN:3128` and `:1080` relay to them. Env vars point tools at `localhost:3128`/`1080`. With no sockets the
  sandbox has no network at all (:3197).
- [F] seccomp: a prebuilt static `apply-seccomp` (x64/arm64) blocks `socket(AF_UNIX, …)` and `io_uring_*` with
  EPERM. It runs *after* the socat relays start and inside a nested user+PID+mount namespace as a non-dumpable PID 1,
  so the workload cannot ptrace the unfiltered helpers (README.md:806-832). Limits: it does not stop use of
  inherited or `SCM_RIGHTS` fds, and 32-bit `socketcall()` can bypass it (generate-seccomp-filter.ts:142-147). Without
  seccomp, Unix sockets are **unrestricted**, with only a warning (README.md:398-399). On Linux `allowUnixSockets` is
  ignored because seccomp can't filter by path (sandbox-config.ts:762-766).
- [F] Linux violation reporting: the README still says bwrap has none, so use `strace` (README.md:849). The code,
  however, has `linux-violation-monitor.ts`, where apply-seccomp USER_NOTIF reports write-intent syscalls over a
  bind-mounted fs socket, and the comment says they are "diagnostic hints and must never gate a policy decision"
  (linux-violation-monitor.ts:58-80). **README and code disagree.**
### Why a sandboxed process cannot bypass the proxies
- [F] Linux: there is no network namespace route at all. The only way out is a bind-mounted Unix socket to the host
  proxy. A tool that ignores `HTTP_PROXY` simply fails to connect (README.md:895-897 "Linux proxy bypass" is about
  *failing*, not escaping).
- [F] macOS: Seatbelt permits outbound only to the proxy's localhost port(s), plus loopback if `allowLocalBinding`.
- [F] Proxy authentication: every CONNECT or absolute-URI request must carry `Proxy-Authorization: Basic
  base64("srt[.<encodedCommand>]:<token>")` with a per-session token, or it gets a 407. The reason given is that
  "any host process can dial 127.0.0.1" (http-proxy.ts:200-208, 426-432). SOCKS5 requires the same token as its
  user/pass (socks-proxy.ts:40-47). The encoded command attributes denials to a command.
- [F] Windows: the WFP `ALE_AUTH_CONNECT` filter is the boundary, and env vars are only hints (README.md:707).

## 2. The egress proxy
- [F] **HTTP proxy** (`http-proxy.ts`) handles CONNECT (:267) and absolute-URI plain HTTP (:673).
  **SOCKS5** (`socks-proxy.ts`) handles other TCP such as SSH and databases; only CMD=CONNECT is accepted
  (socks-proxy.ts:369), so there is no UDP ASSOCIATE or BIND. A mux serves both on one port by peeking the first byte
  (mux-proxy.ts:10-20). SSH runs through SOCKS via an injected `GIT_SSH_COMMAND … ProxyCommand='nc -X 5 …'`
  (sandbox-utils.ts:803-813).
- [F] **Matched value:** the CONNECT request-target host:port (http-proxy.ts:434-450) or the absolute-URL host
  (:673-682). The host is canonicalized (lowercase, trailing dot, inet_aton shorthand such as `127.1`). Hosts with
  control characters are rejected (sandbox-manager.ts:349-366). The forwarded `Host` header is **rewritten** from the
  canonical host (http-proxy.ts:716-724). **SNI is not checked on opaque tunnels**, and the proxy "does not
  terminate or inspect TLS traffic" by default [SBX]. [I] That is why domain fronting works (see §7).
- [F] **Matching** (domain-pattern.ts:109-137): exact, case-insensitive; `*.x.com` matches subdomains only (not the
  apex, and never IP literals); bare `*` matches everything. The optional `:port` suffix restricts to that port. IPv6
  must be bracketed.
- [F] **Order** (sandbox-manager.ts:332-410): `deniedDomains` first (the deny wins, with an optional
  `deniedDomainReasons` text shown to the model). Then `allowedDomains`. Then, if nothing matched: deny when there is
  no ask callback **or `strictAllowlist: true`**, otherwise call `sandboxAskCallback({host,port})`, where a user
  decision allows or denies and a callback error means deny.
- [F] **Resolved-address guard:** before a direct dial, the proxy resolves the allowed name once, drops loopback,
  link-local, multicast, cloud-metadata (incl. 100.100.100.200 and 168.63.129.16), the host's own interface
  addresses, deny-listed IP literals and `deniedResolvedAddresses`, and dials the surviving address with no second
  lookup. RFC1918 is *not* denied by default. The guard is skipped for `parentProxy`/`mitmProxy` routes
  (README.md:360-370).
- [F] **DNS:** the sandbox has no resolver path (netns on Linux, loopback-only Seatbelt on macOS). Clients must send
  names to the proxy. `NO_PROXY` deliberately omits `*.local` so those resolve on the host side (sandbox-utils.ts:
  725-741), and SOCKS uses `socks5h` semantics (:817). [I] DNS-tunnel exfiltration from inside is closed, but the
  host resolver still receives lookups for any name the proxy is asked to check.
- [F] **HTTPS interception is opt-in:** `network.tlsTerminate` (experimental) uses an in-process MITM with an
  ephemeral or configured CA injected via `SSL_CERT_FILE`/`GIT_SSL_CAINFO` etc. It enables `filterRequest`, a
  per-request callback over a web `Request` that returns allow/deny with a reason and gives a 403 on deny or throw
  (request-filter.ts:1-28; sandbox-config.ts:810-822). `excludeDomains` tunnels hosts opaquely for mTLS or pinning
  (README.md:372-377). The alternatives are `mitmProxy` (Unix socket upstream), `parentProxy` (corporate), or external
  `httpProxyPort`/`socksProxyPort`, which make the external proxy responsible for filtering (sandbox-config.ts:780-807).
- [F] **On violation:** the proxy blocks with a 403 carrying `X-Proxy-Error: blocked-by-sandbox-runtime` (HTTP/
  CONNECT) or "connection not allowed by ruleset" (SOCKS). It records the denial in an in-memory ring of 100
  violations (sandbox-violation-store.ts:10-30). `annotateStderrWithSandboxFailures` appends a `<sandbox_violations>`
  block to the command's stderr for the model (sandbox-manager.ts:2335-2353). macOS file and exec denials come from
  `log stream` over the kernel sandbox log (macos-sandbox-utils.ts:1506-1570). In Claude Code, an unknown host
  → **prompt** [SBX] ("Yes" = this session; "Yes, and don't ask again" = saves a `WebFetch(domain:…)` allow rule).
- [F] **Non-HTTP traffic:** TCP goes via SOCKS5 CONNECT and is domain-filtered the same way. UDP and ICMP have no path.
  Local port binding is off by default, and on macOS `allowLocalBinding` enables it. [SREF] says the Linux behaviour
  of `allowLocalBinding` is not stated. [I] Inside a Linux netns the process can bind loopback but only reaches
  itself.
- [F] **Config** is `~/.srt-settings.json` or `--settings` (README.md:307-313), with a Zod schema at
  sandbox-config.ts:720-1190. Top-level keys: `network{allowedDomains, deniedDomains, deniedDomainReasons,
  strictAllowlist, deniedResolvedAddresses, allowUnixSockets, allowAllUnixSockets, allowLocalBinding, allowMachLookup,
  httpProxyPort, socksProxyPort, mitmProxy, parentProxy, tlsTerminate, filterRequest}`, `filesystem{denyRead,
  allowRead, allowWrite, denyWrite, disabled}`, `credentials`, `ignoreViolations`, `enableWeakerNestedSandbox`,
  `enableWeakerNetworkIsolation`, `allowAppleEvents`, `mandatoryDenySearchDepth`, `seccomp`, `git`, `windows`.
  Defaults: network restriction is on **iff `allowedDomains` is defined** (an empty array means block all;
  sandbox-manager.ts:1736-1747). Before v0.0.16 an empty allowlist failed open (GHSA-9gqj-5w7c-vx47). A
  `--control-fd` lets the caller hot-update the config (README.md:187).
- [F] **Credential masking** is directly relevant to worker-jail. With `credentials.envVars/files` in
  `mode:"mask"`, the sandbox sees `fake_value_<uuid4>` (length-matched), and the host proxy swaps sentinel→real in
  headers and bodies only for `injectHosts` (default: `allowedDomains`). The map lives only in memory
  (credential-sentinel.ts:1-9). It **requires `tlsTerminate`** (sandbox-config.ts:1447-1456), and plaintext inject is
  off by default (:688-695). AWS SigV4 is re-signed at the proxy, and unre-signable shapes are denied by default. JWT
  claim masking is supported. Several paths **fail open** with a stderr warning when an `extract` regex or JWT decode
  doesn't match (sandbox-config.ts:479-530). On macOS, file masks degrade to read-deny.

## 3. Filesystem policy
- [F] Reads are allow-by-default. `denyRead` carves out regions and `allowRead` re-allows inside them (allowRead
  wins). Writes are deny-by-default, `allowWrite` opens them and `denyWrite` wins (README.md:115-120, 717-735).
  Implicitly writable: stdio, `/tmp/claude`, `~/.npm/_logs`, `~/.claude/debug` (sandbox-utils.ts:530-547). macOS
  uses gitignore-style globs. Linux binds literal paths for writes and expands read globs at wrap time, so later files
  are not covered (README.md:403-430).
- [F] **Mandatory write-deny** (sandbox-utils.ts:11-39; macos-sandbox-utils.ts:96-127) covers these files in the cwd
  and at any depth: `.gitconfig .gitmodules .bashrc .bash_profile .zshrc .zprofile .profile .ripgreprc .mcp.json`.
  Directories: `.vscode .idea .claude/commands .claude/agents .git/hooks`, plus `.git/config` unless `allowGitConfig`.
  Path comparisons are lowercased against case-insensitive FS tricks (sandbox-utils.ts:41-53). On Linux, ripgrep
  scans to depth `mandatoryDenySearchDepth` (default 3, range 1–10). Paths that don't exist yet are covered with a
  read-only `/dev/null` mount point, and protected ancestors are "pinned" so they can't be renamed (EBUSY)
  (README.md:756-804).
- [F] **Claude Code protects more than srt's list:** `.claude` settings/skills/agents/commands/hooks, `.mcp.json`,
  rc files, `.gitconfig`, `.git/hooks`+`config`, bare-repo `HEAD/objects/refs`, most of `~/.claude`, `~/.claude.json`,
  and `.credentials.json`. "There is no way to exempt one of these paths" [SBX]. [I] Claude Code passes these as
  extra denyWrite. GHSA-ff64-7w26-62rf shows `.claude/settings.json` was once unprotected when absent at startup,
  which allowed persistent hooks to run on the host.
- [F] **Symlinks:** a write is judged where it lands after following links, and a link out of an allowed dir gets
  nothing. Hard links that already exist are a gap on Linux, and nothing is promised on macOS (README.md:737). On
  Linux read rules match by name, so a planted link can't re-open a denied path, and deny mounts land on the real
  path (README.md:739-745, 425-427). Advisories show the **host-side** process following sandbox-made symlinks was the
  real escape (GHSA-vp62-r36r-9xqp, GHSA-4q92/66m2 "deny bypass through symlink", GHSA-7835 worktree `.git` confusion
  → `.zshenv` overwrite).
- [F] Claude Code default: "read access to the entire computer … still allows reading … `~/.aws/credentials` and
  `~/.ssh/`"; "There is no built-in credential deny list". Writes are allowed to cwd, `--add-dir` directories and
  `$TMPDIR` [SBX].

## 4. Claude Code integration
- [F] Scope: only **Bash, PowerShell, Monitor** commands and their children are sandboxed. Read/Edit/Write and
  WebFetch run in the Claude Code process under permission rules. MCP servers and command hooks "run unconstrained
  on the host" [SBX][SENV]. To wrap the whole CLI, use `npx @anthropic-ai/sandbox-runtime claude` [SENV].
- [F] Keys and defaults (checked against the raw [SREF]): `sandbox.enabled` false; `autoAllowBashIfSandboxed`
  **true**; `allowUnsandboxedCommands` **true**; `excludedCommands` unset (Bash rule syntax, must cover every
  subcommand); `failIfUnavailable` false (**by default, missing deps mean the command runs unsandboxed with a warning**);
  `network.allowedDomains` unset (prompts per new host); `strictAllowlist` false; `allowManagedDomainsOnly` /
  `filesystem.allowManagedReadPathsOnly` are managed-only; `tlsTerminate`, `credentials` (mask honored only from
  user/managed/`--settings`, never from the repo); `bwrapPath`/`socatPath` are managed-only. Permission rules merge
  in: `Edit` allow → allowWrite; `Read`/`Edit` deny → fs denies; `WebFetch(domain:…)` → network allow/deny (only
  `*.` and bare `*` wildcards honored) [SBX][PERM].
- [F] Escape hatch: after a violation the model may retry with `dangerouslyDisableSandbox: true`. The retry "runs
  outside the sandbox, so it goes through the regular permission flow" (prompt in Manual, classifier in auto).
  `allowUnsandboxedCommands:false` ("strict mode") makes Claude Code ignore the parameter. An ask rule
  `Bash(dangerouslyDisableSandbox:true)` forces a prompt [SBX].
- [F] `autoAllowBashIfSandboxed` (still the current name): sandboxed Bash runs without a prompt, but deny rules,
  content-scoped ask rules and critical-path `rm` are still honored. "Bash commands that modify files within the
  sandbox boundaries execute without prompting, even in Manual mode" [SBX]. The engineering post claims this cut
  prompts by 84% [ENG].

## 5. Permission model
- [F] Modes: `default` (Manual), `acceptEdits`, `plan`, `auto` (classifier; the default interactive mode since
  v2.1.283 per [MODES]), `dontAsk` (auto-deny anything that would prompt), and `bypassPermissions` ("only … isolated
  environments … without internet access", refused as root outside a recognized sandbox). Deny rules still block in
  bypass. Protected-path writes are allowed in bypass, denied in dontAsk, and **cannot be pre-approved by allow
  rules** [MODES][PERM]. `auto`/`bypassPermissions` cannot be set from project or local settings [SREF].
- [F] Rules: `Tool` or `Tool(specifier)`. Bash uses `*` globs, compound-aware (each subcommand must match), and
  strips wrappers like `timeout`/`nohup`. Read/Edit use gitignore paths (`//abs`, `~/`, `/`=settings-relative). Other
  forms: `WebFetch(domain:x)`, `mcp__server__tool`, and parameter rules `Tool(param:value)`. Evaluation is **deny →
  ask → allow, first match wins**, and a deny at any scope is final [PERM]. Bash argument rules are "not a security
  boundary" (`/usr/bin/curl` and `sh -c` bypass `Bash(curl *)`), and Read/Edit denies don't cover arbitrary
  subprocesses. The docs say "enable the sandbox" for that [PERM].
- [F] Settings precedence: managed > CLI `--settings` > `.claude/settings.local.json` > `.claude/settings.json` >
  `~/.claude/settings.json`. Lists merge [SET]. Managed paths: `/Library/Application Support/ClaudeCode/`,
  `/etc/claude-code/` (user-writable on WSL!), and `C:\Program Files\ClaudeCode\`, plus MDM and server-managed.
  Managed-only locks include `allowManagedPermissionRulesOnly`, `allowManagedHooksOnly`,
  `allowManagedMcpServersOnly`, and `permissions.disableBypassPermissionsMode: "disable"`. Sandbox arrays such as
  `excludedCommands` can still be **widened** by developers, and "has no equivalent managed-only lockdown" [SBX][MSET].
  An unparseable managed file means Claude Code refuses to start [MSET].
- [F] Hooks: PreToolUse exit 2 blocks the call **before** rules are evaluated. JSON `permissionDecision:
  allow|deny|ask|defer` plus `updatedInput`. A hook "allow" can't override a deny or ask rule [HOOKS][PERM].

## 6. Claude Code on the web (cloud)
- [F] Each session runs in an "isolated, Anthropic-managed VM" (4 vCPU / 16 GB / 30 GB), and VMs are reclaimed after
  inactivity [WEB][CENV][SEC]. **Disagreement:** CLI text in [WEB] says "cloud container", and the hypervisor or
  container technology is not stated anywhere. Whether `sandbox.*` (the Bash sandbox) also runs inside the VM is not
  stated.
- [F] Network levels: **None**, **Trusted** (default: package registries, GitHub, cloud SDKs), **Full**, **Custom**
  (own list ± defaults). "All outbound internet traffic … passes through" a security proxy that does malicious-request
  protection, rate limiting, content filtering and "a DNS-level audit trail of requested hostnames" [CENV]. Whether it
  intercepts TLS is not stated. **Even at None**, the Anthropic API, GitHub proxy, MCP connectors and API-credential
  hosts stay reachable ("may allow data to exit the VM") [CENV][WEB]. There is no org-level allowlist push [CENV].
- [F] The Trusted list (full list in `docs-notes.md` §4) covers Anthropic, GitHub/GitLab/Bitbucket incl.
  `gist.github.com` and `*.githubusercontent.com`, container registries, `*.googleapis.com`, `*.amazonaws.com`,
  `*.r2.cloudflarestorage.com`, the major package managers, distros, and datadog/honeycomb intake. [I] Many of these
  are attacker-writable storage, so Trusted is not an exfiltration boundary.
- [F] GitHub proxy: the git client in the VM holds a **scoped, short-lived session credential**. The proxy verifies it
  and swaps in the real token (stored encrypted server-side, "never enter[s] the session VM"). `git push` is limited
  to the session's current branch, API and release-asset requests reach only attached repos, and GraphQL is limited to
  a pinned operation set (others get a 403) [CENV][SEC][ENG].
- [F] Secrets: environment variables (`.env` format) become ordinary env vars "any command Claude runs can read", and
  the UI warns against secrets. API credentials (Pro/Max): "Anthropic's agent proxy adds the key to requests for the
  hosts you list, after each request leaves the session's VM. The key never reaches Claude, the commands it runs, or
  the session's environment variables" [CENV]. Cloud ignores local managed/user settings (server-managed only) and
  doesn't honor `bypassPermissions`/`dontAsk` as defaultMode [SET][MODES].

## 7. Limitations and known bypasses
- [F] Documented [SBX][README.md:881-893]: "not a complete isolation boundary". Allowing broad domains like
  `github.com` enables exfiltration, e.g. push to any repo. Domain fronting works because the allow decision uses the
  client-supplied hostname without TLS inspection, and the fix is a TLS-terminating proxy ("active area of
  development"). Allowing `docker.sock` ≈ host root. Writable `$PATH`/rc/system-config dirs lead to cross-context
  code exec. `enableWeakerNestedSandbox` and `allowAppleEvents` greatly weaken isolation. On Linux without seccomp,
  Unix sockets are open. `filesystem.disabled`+auto-allow lets a command rewrite `~/.claude/settings.json` to widen
  itself. Docker is incompatible, and the suggested fix, `excludedCommands`, runs it unsandboxed. Default read-all
  plus inherited env exposes secrets.
- [F] Not stated in any source: DNS exfiltration, timing channels, and `allowLocalBinding` risks on Linux.
- [F] Advisories (srt): GHSA-9gqj-5w7c-vx47, where an empty allowlist didn't enforce the network sandbox (<0.0.16).
  (claude-code, high unless noted): GHSA-7835-87q9-rgvv worktree/`.git` confusion → host code exec;
  GHSA-vp62-r36r-9xqp sandbox-created symlink followed by the unsandboxed writer; GHSA-ff64-7w26-62rf absent
  `settings.json` injectable → host hooks; GHSA-fg94-h982-f3mm (medium), where a pre-approved `huggingface.co` in
  WebFetch was an OOB exfil channel; GHSA-vhw5-3g5m-8ggf `startsWith()` domain check; GHSA-x5gv-jw7f-j6xj permissive
  safe-command allowlist → read+exfil; repeated command-injection/validation bypasses (sed, find, echo, rg, zsh
  clobber, cd) of Bash approval (GHSA-7mv8, -qgqw, -x56v, -qxfv, -q728, -66q4, -mhg7, -xq4m); several
  trust-dialog-before-execution bugs (GHSA-5hhx, -4fgq, -mmgp, -q5hj, -jh7p).
- [F] Source tensions: [ENG] states no caveats, while [SBX] lists fronting and broad domains. The "credentials never
  in the sandbox" claim [ENG] holds for cloud git only, since the local default reads `~/.ssh` and `~/.aws` [SBX].
  [SEC] "network command approval" for curl/wget is text matching only [PERM]. `allowUnixSockets` is macOS-only
  [SREF] but [SBX] Limitations omits that. The README says Linux has no violation reporting, but the code has a
  seccomp-notify monitor.

## 8. Relevant to worker-jail
**(a) Allowlisted egress proxy for jailed calls**
- [F] The proxy runs outside the jail, and the only network path is a Unix socket (Linux) or localhost port (macOS).
  Env vars are hints and the kernel/netns is the boundary. Per-session proxy auth tokens stop other local processes
  from riding the proxy.
- [F] Match on the CONNECT authority / absolute-URI host, canonicalized. Deny list first, then allow, then
  ask-or-deny. `strictAllowlist` makes the list deterministic. `*.x` excludes the apex. `:port` pins are supported.
  Resolve once and dial the checked IP, blocking loopback, link-local, metadata and self addresses (add RFC1918
  yourself).
- [F] Without TLS termination, a hostname allowlist does not stop domain fronting or exfil to broad hosts. srt's
  answer is opt-in `tlsTerminate` + `filterRequest` (method/path policy) and an injected CA. [I] worker-jail should
  either terminate TLS for policy hosts or accept that fronting is in scope. It should also avoid storage-like
  wildcards (the cloud Trusted list is an anti-example).
- [F] Violations are returned in-band to the model (`<sandbox_violations>`, 403 with reason, `deniedDomainReasons`),
  which lets the agent adapt instead of retrying blindly. The Linux violation monitor is explicitly non-authoritative.
- [F] Fail-open pitfalls seen in practice: an empty allowlist (GHSA-9gqj), missing deps meaning unsandboxed unless
  `failIfUnavailable`, and seccomp absent meaning Unix sockets are open. [I] worker-jail should fail closed on all of
  them.
**(b) Protected paths**
- [F] Baseline write-deny set: shell rc files, `.gitconfig`, `.gitmodules`, `.git/hooks`, `.git/config`, `.mcp.json`,
  `.ripgreprc`, `.vscode`, `.idea`, and `.claude/{commands,agents}`. Claude Code adds `.claude` settings/hooks/skills,
  `~/.claude*`, and bare-repo `HEAD/objects/refs`. It applies at any depth, is case-insensitive, and covers paths that
  **don't exist yet** (the missed case in GHSA-ff64).
- [F] Symlink/hard-link and worktree confusion are the recurring escape class, especially when a **privileged
  host-side writer** later follows a path the jailed process shaped. [I] Any host-side component that writes into the
  workspace (patch apply, artifact export) must resolve paths itself with no-follow semantics.
**(c) Credentials injected outside the sandbox**
- [F] Two first-party patterns: the cloud GitHub proxy (scoped session credential in the VM, swapped at the proxy,
  with branch/repo/GraphQL-operation policy) and srt `credentials` `mask` (sentinel inside, real value substituted by
  the proxy only for `injectHosts`, only over terminated TLS, and SigV4 re-signed). Cloud API keys are added "after each
  request leaves the session's VM".
- [F] Caveats: masking fails open on extract/JWT mismatch by default (use `onExtractNoMatch:"deny"|"error"`). macOS
  file masks become read-deny. Env vars set in a cloud environment are plain and readable. [I] worker-jail should
  prefer the swap-at-proxy model and treat any secret in the jail env as exfiltratable.
**(d) Approvals**
- [F] The sandbox replaces most approvals (auto-allow inside the boundary). Anything leaving the boundary
  (`dangerouslyDisableSandbox`, new domain, protected path) falls back to a prompt or classifier. Strict mode removes
  the escape hatch. Deny → ask → allow, and deny is final across scopes. Hooks can block (exit 2) but not override
  denies. Managed settings can lock rules, domains and read paths, but not `excludedCommands`.
- [F] Bash text rules are explicitly not a security boundary. [I] worker-jail approvals should key on the enforced
  effect (host, path, credential use), not on command strings, and new-domain approvals should be per-command or
  per-session rather than persisted into project-writable config (compare GHSA-ff64 and the settings-injection
  advisories).
