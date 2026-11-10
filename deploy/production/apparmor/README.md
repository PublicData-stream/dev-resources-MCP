`devres-runtime` is an optional, dedicated Apache-2.0 AppArmor policy. Its SHA-256
is `4375146629c956b8e63cc4b358ef52c6bcda458621b7dcf8601b0f3d922b3e7e`.
Do not edit the installed policy independently of its reviewed hash and deployment
settings. The production operator verifies it but never installs, loads or unloads
profiles, changes sysctls, or modifies either runtime's default profile.

The policy adapts these exact upstream container templates; retained original
source files and the complete [Apache license](Apache-2.0.txt) accompany it:

| Source | Revision | Template SHA-256 |
| --- | --- | --- |
| [k3s containerd](https://github.com/k3s-io/containerd/blob/605c492164bf52dfbf3fb1c9a2388f2483579f77/contrib/apparmor/template.go) | `605c492164bf52dfbf3fb1c9a2388f2483579f77` | `f5bef9dd4d785a27aa00b421862c68de973f19bb5b36dd39f4a5d2dd35ac2683` |
| [Moby vendored container profile](https://github.com/moby/moby/blob/70efc0e31da3a115fc87574d1b786fa2b867c346/vendor/github.com/moby/profiles/apparmor/template.go) | `70efc0e31da3a115fc87574d1b786fa2b867c346` | `cce1c730656ad73cb04b19bf25caa2351732a00e04a06eeaf3010105e1ba6a57` |

Copyright The docker Authors, The Moby Authors, and The containerd Authors.
Adaptation names one dedicated profile, retains the intersection of baseline
permissions and union of baseline denials, and adds only exact same-profile
stacked-peer signals for `devres-runtime//&unconfined`. Docker's AF_ALG and
AF_VSOCK denials remain, and the optional CRI RootlessKit receive allowance is
omitted for the rootful target. All proc/sys/mount restrictions remain. No stacked
ptrace or wildcard peer permission is added. UID, PID namespaces, capabilities,
seccomp and other Kubernetes/Docker boundaries continue to apply independently.

Ubuntu AppArmor stacking can deny required process signals despite the baseline
self-peer allowance; see [containerd's report](https://github.com/containerd/containerd/issues/14485).
This policy specifically addresses that observed behavior. Parser compilation
alone does not establish successful process signaling or PostgreSQL readiness.

After explicit host-security approval, independently install only this exact file
at `/etc/apparmor.d/devres-runtime`, root:root, mode0644, with no symlinks or hard
links. Refuse an unknown pre-existing file/profile. Validate with the target's
`apparmor_parser -Q -K --abort-on-error` before loading only the dedicated profile.
Verify its enforcing state. Keep the runtime defaults and AppArmor sysctls intact.
Require zero desired/observed replicas and record workload UIDs/resourceVersions,
canonical settings/manifests and their preimages before selecting the setting.
Patch only the selected Pod profile fields using identity/resourceVersion tests;
update the canonical bundle and settings hash together under the operator lock.

Run bounded, isolated same-profile SIGURG/SIGUSR1/SIGTERM fixtures under UID70 and
65532 before starting the existing PostgreSQL data. Keep writer/serving stopped
until their other gates pass. Verify unchanged PV/PVC/data identities, stable SQL
readiness, intended database roles/grants and absence of fresh signal denials.
The isolated rehearsal containers require an explicit `apparmor=devres-runtime`
security option; the production renderer does not configure the Docker daemon.
These files provide no production or reboot acceptance receipt.

Rollback stops the affected workloads and owned rehearsal containers first,
preserving all data and the PostgreSQL startup-probe repair. Restore only recorded
Pod profile fields/canonical bundle while replicas remain zero. Verify no tasks
remain attached to this profile, including stacked labels, before unloading and
removing only the exact owned profile/file. Never unload a profile from running
tasks, alter default profiles/sysctls, or claim that the prior stopped default
profile state resolves the host's signal regression.
