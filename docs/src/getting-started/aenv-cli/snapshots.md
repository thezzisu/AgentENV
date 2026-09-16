# Snapshots

`aenv snap` is an alias for `aenv snapshot`, including its `create` and `list`
subcommands.

## `aenv snapshot create <sandbox-id>`

Capture a persistent snapshot from a running sandbox. The snapshot can be used as a template to start new sandboxes with `aenv start`.

```bash
aenv snapshot create <sandbox-id>
aenv snapshot create <sandbox-id> --name my-base
```

| Flag | Description |
|------|-------------|
| `--name <name>` | Snapshot name or alias. If omitted, the generated snapshot ID identifies the snapshot. |

When source-registry image publication is enabled on the server, the command
also prints the published OverlayBD-native image reference on an `Image:` line;
that reference can be passed to `aenv start --cold <image-reference>`.

### Nested virtual machines

The bundled Firecracker does not save nested KVM vCPU state. Before an outer
pause, snapshot, fork, or template capture, AgentENV terminates guest processes
holding KVM VM/vCPU descriptors (including processes inside Docker) and waits
for the descriptors to close. Unresponsive VMMs are killed after a grace period.
This also stops the nested VM in the source sandbox. Shut it down normally first
if its application data needs a clean shutdown; nested RAM state is discarded.

The outer sandbox remains usable after restore and can start new nested VMs.
VMMs that are systemd service main processes and Docker containers in systemd
cgroups are stopped through their managers, suppressing automatic restarts.
Stop other VM supervisors and concurrent VM launches before capture. If a VM
respawns during cleanup or envd cannot complete the cleanup, the capture fails
instead of publishing a snapshot that could hang on restore.

## `aenv snapshot list`

List persistent snapshots. Alias: `aenv snapshot ls`, `aenv snap ls`.

```bash
aenv snapshot list
aenv snapshot list --sandbox-id <sandbox-id>
```

| Flag | Description |
|------|-------------|
| `--sandbox-id <id>` | Filter snapshots by source sandbox ID |
| `--output <table\|json>` | Output format. Defaults to table on a TTY and JSON when redirected. |

The table output includes an `IMAGE REF` column (`-` when no image was published); JSON output includes the optional `imageRef` field.

To delete a snapshot, use `aenv template delete <snapshot-id>` or `aenv template delete <name>` — snapshots share the same underlying store as templates and are deleted through the same command.

