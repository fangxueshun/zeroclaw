# ZeroClaw Operations Runbook

This runbook is for operators who maintain availability, security posture, and incident response.

Last verified: **February 18, 2026**.

## Scope

Use this document for day-2 operations:

- starting and supervising runtime
- health checks and diagnostics
- safe rollout and rollback
- incident triage and recovery

For first-time installation, start from [one-click-bootstrap.md](../setup-guides/one-click-bootstrap.md).

## Runtime Modes

| Mode | Command | When to use |
|---|---|---|
| Foreground runtime | `zeroclaw daemon` | local debugging, short-lived sessions |
| Foreground gateway only | `zeroclaw gateway` | webhook endpoint testing |
| User service | `zeroclaw service install && zeroclaw service start` | persistent operator-managed runtime |

## Baseline Operator Checklist

1. Validate configuration:

```bash
zeroclaw status
```

2. Verify diagnostics:

```bash
zeroclaw doctor
zeroclaw channel doctor
```

3. Start runtime:

```bash
zeroclaw daemon
```

4. For persistent user session service:

```bash
zeroclaw service install
zeroclaw service start
zeroclaw service status
```

## Health and State Signals

| Signal | Command / File | Expected |
|---|---|---|
| Config validity | `zeroclaw doctor` | no critical errors |
| Channel connectivity | `zeroclaw channel doctor` | configured channels healthy |
| Runtime summary | `zeroclaw status` | expected provider/model/channels |
| Daemon heartbeat/state | `~/.zeroclaw/daemon_state.json` | file updates periodically |

## Logs and Diagnostics

### macOS / Windows (service wrapper logs)

- `~/.zeroclaw/logs/daemon.stdout.log`
- `~/.zeroclaw/logs/daemon.stderr.log`

### Linux (systemd user service)

```bash
journalctl --user -u zeroclaw.service -f
```

## Incident Triage Flow (Fast Path)

1. Snapshot system state:

```bash
zeroclaw status
zeroclaw doctor
zeroclaw channel doctor
```

2. Check service state:

```bash
zeroclaw service status
```

3. If service is unhealthy, restart cleanly:

```bash
zeroclaw service stop
zeroclaw service start
```

4. If channels still fail, verify allowlists and credentials in `~/.zeroclaw/config.toml`.

5. If gateway is involved, verify bind/auth settings (`[gateway]`) and local reachability.

## Safe Change Procedure

Before applying config changes:

1. backup `~/.zeroclaw/config.toml`
2. apply one logical change at a time
3. run `zeroclaw doctor`
4. restart daemon/service
5. verify with `status` + `channel doctor`

## Rollback Procedure

If a rollout regresses behavior:

1. restore previous `config.toml`
2. restart runtime (`daemon` or `service`)
3. confirm recovery via `doctor` and channel health checks
4. document incident root cause and mitigation

## Service Environment (Linux systemd)

When ZeroClaw runs as a user service, it needs access to user-installed tools (Python, pyenv, conda, etc.). The systemd unit includes:

- **Default PATH**: `~/.local/bin`, `~/.pyenv/shims`, `~/miniconda3/bin`, `~/anaconda3/bin`, plus `/usr/local/bin`, `/usr/bin`, `/bin`
- **Optional env file**: `~/.zeroclaw/zeroclaw.env` — if present, each line `KEY=VAL` is loaded and overrides the default. Use this for custom PATH or other variables.

Example `~/.zeroclaw/zeroclaw.env`:

```bash
# Custom PATH (override default)
PATH=/home/me/.local/bin:/home/me/.venv/bin:/usr/local/bin:/usr/bin:/bin

# Extra vars passed to shell tool (see autonomy.shell_env_passthrough in config)
# DATABASE_URL=...
```

After creating or editing `zeroclaw.env`, run `zeroclaw service restart` to apply.

**macOS launchd**: The plist does not support an env file. To pass custom env, either run `zeroclaw daemon` in a terminal with the desired environment, or use a wrapper script that sources your env and execs zeroclaw.

## Related Docs

- [one-click-bootstrap.md](../setup-guides/one-click-bootstrap.md)
- [troubleshooting.md](./troubleshooting.md)
- [config-reference.md](../reference/api/config-reference.md)
- [commands-reference.md](../reference/cli/commands-reference.md)
