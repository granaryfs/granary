<!-- SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Operating client enrollment

A granary server admits an authenticated client only if the digest of its
certificate's public key is **enrolled**: recorded in the server's enrollment
set. Each entry binds the public key digest to a principal and that
principal's tenant. The set is one file,
`ENROLLMENT`, in a directory on the server's host. Only the local
`granary-server enrollment` verbs write it; nothing on the wire does. This page
is for whoever keeps that directory: how to provision it, who runs the verbs,
what each one does, and what the server answers when the file is not
readable. Use the enrollment commands below to create and update the file.

Set `GRANARY_AUTHORITY_ENROLLMENT_DIR` to the directory's absolute path.
See the [publication authority configuration](operating-the-server.md#the-publication-authority)
for the server's other required settings.

## Provisioning the directory

Create the directory before the first verb, owned by the uid the server runs
as, mode 0700 (no group or other access of any kind):

```
install -d -o granary -g granary -m 0700 /var/lib/granary/enrollment
```

The directory must pass the **protection rule**, which the server checks at
startup and every verb checks before it reads anything:

- **the directory** is a real directory (no symbolic link at its name), owned
  by its owner `O`, with **no group or other access at all**: mode 0700 or
  stricter, so a 0750 or 0705 directory is refused. The verbs' lock is the
  directory itself, and whoever can open the directory could hold it. The
  server requires `O` to be its own effective uid; a server running as root
  needs a root-owned directory;
- **every ancestor**, from `/` down, is a real directory owned by root or by
  `O`, and either not writable by group or other or sticky (`/tmp` is
  allowed: in a sticky directory only an entry's owner or root can rename it);
- **the file** `ENROLLMENT`, and the verbs' `ENROLLMENT.tmp`, are regular
  files owned by `O` with no group or other write. Group or other *read* is
  allowed: the file holds digests of public keys and tenant names, no secret;
- **the filesystem** of the directory is ext2/3/4, xfs or btrfs, and of each
  ancestor one of those, overlay or tmpfs. A network or user-space filesystem
  (NFS, CIFS/SMB, 9p, virtiofs, fuse, ceph, or any type the table does not
  know) is refused: its owner and mode bits are not what the server's kernel
  enforces. An explicit acknowledgement lifts the type refusal and nothing
  else. Use `--accept-unsupported-filesystem` for an enrollment command.
  For the running server, set `GRANARY_AUTHORITY_ACCEPT_UNSUPPORTED_FILESYSTEM`
  in the publication authority's configuration.

The checks run on open descriptors, from `/` down with `O_NOFOLLOW` at every
step, so nothing can swap a name between the check and the use. After the
check passes, only root or `O` can change any component: the rule is the trust
boundary, and a change after it is yours.

The server checks the directory **once, at startup**, and refuses to start if
it is missing, not protected, or not searchable by its uid. A missing
`ENROLLMENT` file does not stop it: it starts, and every lookup is unavailable
until the first `mint`.

**Linux only, as a protection claim.** On Linux a POSIX ACL that grants any
named user or group write shows as group write in the mode bits, so the rule
refuses it. **macOS extended ACLs are not checked**, and macOS has no
filesystem type table, so every walk there refuses without the
acknowledgement. macOS is a development venue; the protection rule is not
claimed there.

**Durability of the directory itself is yours.** The verbs sync the file, the
directory and, when they create the first file, the directory's parent. The
ancestors above the parent are the operator's provisioning: create them on a
filesystem that has made them durable before the first enrollment.

## Who runs the verbs

The directory's owner, or root. A verb run by anyone else is refused. A verb
run as root gives every file it creates to the directory's owner (and the
directory's group) before it writes anything to it, so the server can always
read what root wrote.

The mutating verbs (`mint`, `attach`, `revoke`, `retire`) take an exclusive
lock (`flock`) on the enrollment directory itself, from before they read the
set until after they sync the directory. Two verbs run at once serialise;
neither change is lost. There is no lock file: nothing is left behind by a
verb that dies, since the kernel releases its lock with the process, and a
file named `LOCK` left by an earlier build is ignored (remove it at leisure).
`list` takes no lock and creates
nothing, so it runs on a read-only directory: the verbs publish a change only
by renaming a whole new file over `ENROLLMENT`, so a read sees the old set or
the new one, never part of either.

Grant mutations in `DEBUG-GRANT` share this protected enrollment directory and
its directory-descriptor lock, including publication syncs. Concurrent enrollment
and grant mutations therefore serialize. See [local debug grants](operating-debug-grants.md).

## Format status

The enrollment set's format is **frozen v1 (2026-10-06)**, with its byte layout
and decoder accept set fixed. Mutating verbs publish the enrollment set; `list`
writes nothing.

## The verbs

```
granary-server enrollment mint    --tenant T --credential C --dir D
granary-server enrollment attach  --principal P --credential C --dir D
granary-server enrollment revoke  --credential C --dir D
granary-server enrollment retire  --principal P --dir D
granary-server enrollment list    --dir D
```

Every verb also takes `--accept-unsupported-filesystem`. `D` is the
directory's absolute path. `C` is a credential: either its written digest,
`clientspki-v1:` followed by 64 lowercase hex characters, or the path of a
PEM certificate file, whose first `CERTIFICATE` block is the client's
end-entity certificate. A pasted TLS server pin (`sha256/…`), root-signing key
(`ed25519:…`) or key locator (`keyid:…`) is refused with a message saying what
it is. `P` is a principal, `principal:` followed by 32 lowercase hex
characters. `T` is a tenant name: 1 to 255 printable ASCII characters, no
space.

| verb | does | prints | refuses when |
|---|---|---|---|
| `mint` | creates a principal under tenant `T` with `C` as its first credential; the principal's id is 16 bytes from the operating system's randomness, never one any principal, active or retired, ever had. The only verb that accepts a missing file (the first enrollment). | `<principal> <digest>` | `C` is already enrolled, to anyone; 16384 principals or 16384 credentials already |
| `attach` | adds `C` to the active principal `P` | `<principal> <digest>` | `P` is absent or retired; `C` is already enrolled; 16384 credentials already |
| `revoke` | removes `C`; its principal stays, active, even with no credential left | `<principal> <digest>` | `C` is not enrolled |
| `retire` | makes `P` permanently unattachable; its record is kept so its id is never reused | `<principal>` | `P` is absent or retired, or still holds a credential (revoke it first) |
| `list` | prints the verdict the server would reach on the file now, then, when it is `ok`, every principal and credential | see below | nothing; an unavailable set is exit 65 |

Every verb except `mint` refuses a missing file ("no enrollment set; mint a
principal first"). Every verb refuses a file that is corrupt, oversize or
unprotected, and never overwrites it: restore it from a backup.

`list` prints, on success:

```
ok principals=2 credentials=3
principal principal:… active acme
principal principal:… retired beta
credential clientspki-v1:… principal:…
```

and on a set the server would not use, one line, `unavailable <reason>:
<detail>`, with exit 65.

### Exit codes

| code | meaning |
|---|---|
| 0 | done (for `list`: the set is `ok`) |
| 64 | usage: an unknown command, verb or flag, a missing or repeated flag, or a value that does not parse (including a certificate file that cannot be read) |
| 65 | refused, **nothing written**: the set refused the change, the directory or a file failed its check, an I/O failure stopped the verb before the rename that publishes a change (locking the directory, removing a leftover `ENROLLMENT.tmp`, reading the set, or creating, writing or syncing the temporary; the message says nothing was changed); for `list`, the set is unavailable |
| 74 | I/O failure from the rename on: the change **may or may not** be visible. Run `list` before retrying |

The bare `granary-server` with no arguments serves exactly as it always has;
any first argument other than `enrollment` is exit 64.

## Rotation

Rotate a client's key with **`attach` then `revoke`**: attach the new
certificate's digest to the principal, deploy the new certificate, then revoke
the old digest. Between the two, both are enrolled. If you revoke first by
mistake, the principal stays active with no credential, and `attach` repairs
it; nothing is lost but the window. A credential that has ever been revoked is
simply absent: enrolling it again is a deliberate `attach` or `mint`.

## What the server answers

For each client that needs a principal, the server's lookup answers one of
three things: **enrolled** (to this principal and tenant), **absent** (the set
was read and the digest is not in it), or **unavailable** with a reason. An
unavailable set is never read as an empty one: the client is neither admitted
nor told it is unknown.

| reason | means | do |
|---|---|---|
| `missing` | no `ENROLLMENT` file | `mint` the first principal, or restore the file |
| `unreadable` | an I/O error reading the file or the directory | check the disk; the next lookup retries |
| `unprotected` | the file is not a regular file, is owned by someone else, or is group- or other-writable (or a symbolic link sits at the name) | fix the owner and mode, or restore it |
| `oversize` | larger than any valid set | restore it from a backup |
| `corrupt` | not a valid set | restore it from a backup |
| `directory` | the configured path does not name the directory the server checked at startup (renamed, replaced, removed) | if a `stat` of the path finds **something else** there (another directory, or not a directory), every lookup stays unavailable until you put the original back and **restart the server**, so a set written into a replacement is never read as the old one; if the `stat` fails (the path is missing, or an I/O error), only that lookup is unavailable, and a later lookup looks again and recovers once the original is back |
| `stalled` | the filesystem did not answer within two seconds | check the disk; the lookup that was waiting is not repeated, the next one waits on the same read |

A change a verb makes is seen by every lookup that **begins after the verb
returns**: the server checks the file's identity (device and inode, mode, owner,
size, modification and change times) on every lookup, and rereads it when it
changed. There is no cache timer.

Editing or copying over `ENROLLMENT` in place is not supported: a rewrite
that keeps the file's size and modification time, made within one tick of
the filesystem's clock of the file's last change, leaves its identity as it
was and is not seen; publish by rename, as under [Backups](#backups).

The server logs one `warn` line when the set becomes unavailable (with the
reason) and one `info` line when it becomes available again, not one per
request. It keeps a counter per unavailable reason, counts of successful
reloads and of failed ones, and its current state with the number of
principals and credentials. The local support export will carry them when it
exists; it is not in this build. The anonymous volume status carries nothing
about enrollment.

## Backups

Back up `ENROLLMENT` with the rest of the host's state; it is small (at most
about 5 MB). **A lost file reopens bootstrap**: the next `mint` starts an
empty set. Nothing previously enrolled becomes enrolled by that, and a revoked
credential stays refused, but every principal's record is gone, retired ones
included, so their ids are no longer guarded against reuse beyond the 128 bits
of randomness each was drawn with. Restore the file from a backup rather than
minting afresh: stop nothing, copy the backup in as a new file owned by the
directory's owner, mode 0600, and rename it over `ENROLLMENT`. The server sees
it on the next lookup.
