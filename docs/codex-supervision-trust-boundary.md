# Linux review supervision: trust boundary proposal

`tucupi recovery status` is a read-only, localized limitations notice. On Linux
it screens the local format marker and pending-attempt record; it does not
inspect processes or services, contact an authority, or authenticate the
record. Missing or invalid state is unknown, not clean; its successful exit
only means the notice printed and it does not authorize recovery.
The direct `llm_verdict` Codex branch now also invokes the Linux recovery
preflight before unconditionally returning unavailable; even a successful
preflight does not enable model execution. An isolated test exercises this
branch with a synthetic supervised child and disposable persisted state. It
does not integrate real Codex execution or establish process-tree cleanup.
Another isolated test runs a fixed synthetic child through the fixture gate,
quarantines a synthetic safe response and records its direct exit. Both the
real preflight and an injected successful preflight still leave Codex disabled.
The fake cgroup and cancellation file are not evidence of containment.
The fixture gate can then restore its own disposable single-file source using
the persisted plan only after a direct exit record is observed. The test
rejects recovery before that record; restoration never clears the attempt or
proves descendant cleanup, and the code must not be used for real projects.
An explicit fixture-only reopening path works without the in-memory gate after
supervisor exit. It requires and rechecks valid direct-exit evidence and the
persisted synthetic post-image; it never adopts or signals a persisted PID.
Exit evidence and checks are unauthenticated and non-atomic, and a failure
after target mutation remains ambiguous.
An isolated race test changes the direct-exit record after the synthetic
target rename but before result publication. Publication is refused, while the
target is already changed and the pending attempt remains blocked. This is not
proof against concurrent same-UID writers between checks.
For interrupted publication, a separate fixture-only resume path observes an
already-restored disposable target and requires a persisted post-image and
valid direct exit, rechecking the exit under the publication lock. It retains
the partial rollback record and pending attempt; its observation does not
prove rollback or cleanup. The older fixture resume remains separate and does
not acquire this direct-exit requirement.
An isolated process test terminates a synthetic recovery worker immediately
after creating its result record and, separately, after writing it but before
sync. The process owning the disposable target then resumes from persisted
records while retaining the original result and pending attempt. Process exit
does not simulate power loss or prove storage durability.
Both reopened recovery and reopened resume retain the originally opened state
directory rather than reopening the name after reading exit evidence. A fixture
test replaces that name with a copy and checks that recovery fails before target
mutation. These identity checks remain point-in-time checks, not protection
against same-UID interference between filesystem operations.
An isolated subreaper test records the direct child's successful exit while a
known synthetic descendant is still alive. The descendant subsequently writes
a disposable marker and is reaped; both before and after that, the persisted
attempt remains blocked and descendant cleanup remains unknown. This test does
not exercise a cgroup or establish real process-tree containment.
With fixture recovery enabled, the same disposable test restores its target
while that descendant is alive, then releases the descendant to overwrite the
target again. The attempt remains blocked and rollback remains unknown. This
intentionally demonstrates why the synthetic restore is not safe real rollback.
The fixture-only target diagnostic separately reports a point-in-time match,
difference, or unavailable/invalid observation after validating the local
rollback record. It does not write, authorize work, prove cleanup, authenticate
records, or provide an atomic view against same-UID interference.
An explicit resume-target diagnostic uses the validated resume record instead
of assuming the interrupted rollback record was complete. It preserves both
records and reports an unavailable observation if resume evidence is invalid.
The single-file fixture gate also exposes that observation for its own bound
disposable target, after checking its captured plan and directory identity.
It does not clear the pending attempt or use the observation for admission.
The gate can also invoke the separate direct-exit-checked fixture resume and
inspect its resume record. An integrated test simulates a partial record and
keeps it, refuses a divergent target or invalid exit, and observes later target
divergence. This simulation is not a process-crash or power-loss proof.
For both fixture recovery and resume, the gate now passes its already-open
state directory through the operation. Replacing the named directory with a
copy causes refusal before fixture mutation or result publication; checks
remain non-atomic against same-UID interference.
The gate's rollback and resume diagnostics also use that retained directory.
A fixture test swaps in a separately opened copy with valid matching records:
the path-only observer can see the copy, but the bound diagnostic refuses it.
The fixture child can now combine quarantined-response presence, direct exit,
and the gate's target observations only for the matching attempt and directory.
This read-only aggregation is non-atomic, does not expose or promote the review
verdict, and reports cleanup and real rollback as unknown.
After fixture recovery and resume, an injected model runner is asserted not to
execute even when an injected recovery preflight succeeds. The production
runner remains unchanged and the real Codex branch remains disabled.
The integrated fixture also exercises an invalid response and, independently,
a valid synthetic response from a failed direct child. Both retain a pending,
blocked attempt through the synthetic recovery and resume sequence; neither
case promotes a response or proves cleanup.
The PKGBUILD review analysis can be exercised with local synthetic sources
after the normal fetch boundary. An isolated process with pending fixture
records returns an inconclusive review for a nontrivial source change when
Codex is disabled; the test does not fetch packages or start the provider.
The same isolated test also exercises the Homebrew formula analysis with local
synthetic source changes and obtains an inconclusive review. It does not run
Homebrew or validate real package fetching.
The source-review worker is now also run after a separate disposable child
exits and a one-file synthetic rollback is recorded. Both source reviews remain
inconclusive; the records and restored fixture remain unchanged. No cgroup
admission or real Codex execution occurs in this test.
The same isolated worker writes synthetic cached "safe" reviews and calls the
public review entry point for both ecosystems. With Codex disabled, cached model
results remain inconclusive despite the fixture recovery record. The test uses
only the disposable cache and does not validate external fetches.
The integrated success fixtures construct their supervised-child wrapper in
the test and do not pass real cgroup admission. A separate test exercises the
actual admission path with a normal disposable directory and confirms that it
refuses admission before releasing the child, preserving the pending records.
Passing real admission remains unverified without a delegated fixture cgroup.
The refused-admission fixture is also inspected after its supervisor process
exits: the pending intent, snapshot, and post-image remain, no direct-exit
record is inferred, and the next attempt stays blocked. This process-exit test
does not establish power-loss durability or descendant cleanup.
A separate CLI integration test models the same kind of pre-binding pending
fixture plan (intent, snapshot and post-image, no exit) after a supervisor
process exits. English and Portuguese status remain read-only and blocked. It
does not invoke the actual cgroup admission rejection path.
Another CLI integration test observes completed single-file synthetic rollback
after successful and failed disposable direct children. Both locales continue
to report a blocked attempt and unknown cleanup/rollback; status preserves the
fixture target and persisted records. No real cgroup admission is involved.
Another integrated fixture case requests cancellation after direct-child exit;
the fake cgroup cannot produce the expected kill handle. Even when that stop
request fails, the pending response is discarded and late responses are
rejected; fixture recovery keeps the attempt blocked and cleanup unknown.
Its local intent, binding and direct-exit reads share a nonblocking advisory
directory lock with participating writers. Lock contention reports unavailable;
non-cooperating same-UID processes can still change records between reads.
An isolated process test exits a synthetic supervisor after spawning a child
but before persisting its locator. Reopened status retains the pending intent
and does not infer cleanup. A separate live sentinel whose PID is inserted as
fixture data remains responsive after status inspection; this demonstrates the
tested path, not a general proof that no signal can ever be sent.
Direct-exit v3 records bind the recorded outcome as well as the validated child
locator or unit binding. Older v1 and v2 exit records are reported inconsistent
and preserved, without automatic migration or deletion. This digest is not
authentication, and stored PIDs remain diagnostic locators, never authority to
adopt or signal.
The local unit-binding reader rejects multiply linked records; this is a
point-in-time consistency check, not protection from same-UID interference.
It also rejects an unterminated binding record, preserving the partial state
instead of interpreting it as a complete write.
An isolated CLI test records success and failure from synthetic direct children,
exits their supervisor and reopens the records in separate status processes in
both languages. It does not validate descendant cleanup or power-loss recovery.
When a valid pending child locator exists but no exit record can be found, the
CLI distinguishes that observation from invalid or unavailable evidence. It
does not infer that the child is alive or that the process tree is clean.
On Linux, `tucupi recovery init` explicitly provisions the local marker under
an existing user-owned non-group/world-writable XDG state base. It does not
overwrite existing recovery state, authorize a provider, or treat an empty
directory as proof that earlier attempts are clean. A failed initialization may
leave an empty `tucupi` parent; it does not automatically delete or repair it.
The same-user recovery building block can explicitly create a private,
create-only pending-intent record and sync it before a future attempt. The
status command recognizes the record after restart, but does not launch work,
verify descendants, execute rollback, or clear it. A partial record remains
unknown; duplicate creation is refused. This primitive is not wired to Codex
execution and is not protected against other processes with the same UID.
If a local intent and attempt record are both present, the diagnostic compares
their attempt identifiers and reports mismatches or partial records as
inconsistent and blocked. Legacy attempt records without an intent remain
readable as unauthenticated observations. These sequential reads do not form an
atomic snapshot or establish process ownership, cleanup, or rollback.
The feature-gated synthetic supervisor can persist this intent before its own
fixture journal and child creation. A test interrupts that supervisor during
creation and reopens both records; execution, descendant cleanup and rollback
remain unverified. The two stores are not atomic, and the test does not prove
process-tree cleanup, rollback, power-loss durability, or real recovery.
That synthetic flow now also writes a matching recovery binding before the
gate release; its unit and invocation identifiers are invented fixture values,
not evidence of real manager ownership. A separate interruption test stops the
supervisor after binding and before release and keeps recovery blocked.
The feature-gated review start gate also offers an explicit same-user recovery
directory. It records intent before permitting its synthetic spawn callback;
failure keeps the gate closed. A process-exit test reopens that record and
refuses a duplicate start. It does not verify descendant cleanup or rollback,
and the production Codex path does not use this experimental gate.
The review fixture delegates intent and child binding to the same-user
production building block rather than maintaining a separate implementation.
On a binding error the fixture retains responsibility for its child; any
published intent or partial locator remains pending and blocks a retry.
The review fixture can also opt in to persisting a synthetic file snapshot
after intent and before child creation. Snapshot errors leave intent pending
and prevent spawn; the snapshot is not an admission or cleanup proof. This
does not connect snapshots to real Codex execution or perform a live rollback.
Before its spawn callback, the fixture reopens the snapshot and compares it to
the one selected at start; corrupt or different content closes that gate. This
check is not atomic with spawn and cannot protect against same-UID interference.
It also rechecks before binding the newly created child. If that fails, the
caller retains the child handle and must attempt cleanup; no child locator is
inferred from a failed check.
The fixture repeats that comparison before releasing the child gate. Failure
permanently closes that gate instance; the child remains the caller's cleanup
responsibility. The recheck is not atomic with release and is not containment.
An integrated synthetic drill reopens that snapshot after the fixture
supervisor exits, restores an isolated copy, and rolls back one file in an
owned temporary target. The integrated drill uses one in-memory snapshot for
both steps and rechecks the persisted snapshot before rollback; a detected
change aborts. The recheck and filesystem change are not atomic, and same-UID
interference with records or target remains outside the boundary. A successful
drill does not clear the pending attempt
or verify descendant cleanup or real rollback.
After the synthetic one-file drill, a create-only fixture result records the
intent identifier; duplicate publication is refused. If publication fails,
the target may already have changed and the result is ambiguous. This record
is not authenticated evidence and is never used to authorize real work.
The fixture-only reader reopens this bounded record and checks its intent ID;
missing, partial, or inaccessible records remain unavailable/invalid. Even a
valid observation is not proof of production rollback or descendant cleanup.
The integrated synthetic recovery flow takes a nonblocking advisory lock on an
independently opened snapshot descriptor until its result is published. It
serializes only cooperating integrated flows using the same inode; direct fixture
helpers and same-UID processes can ignore it or replace the record. It does not
prove ownership, cleanup, or an atomic snapshot, and is not used for Codex.
Recovery and resume compare the lease inode with the named snapshot before
critical steps, refusing a detected replacement even with identical contents.
These checks are point-in-time and do not prevent a later replacement.
A fixture test exits while holding the lock before rollback, then retries into
a different temporary target. The pending intent and the interrupted target
remain; the test does not reconcile or signal the persisted process locator.
Fixture tests interrupt publication immediately after record creation and after
the write but before sync. Both leave the attempt pending and refuse duplicate
publication. A complete-looking record after process exit does not establish
power-loss durability; the synthetic target may already have changed.
The fixture can reconcile that ambiguity only when a disposable target already
matches the synthetic snapshot: it writes a separate create-only observation,
preserving the earlier result and intent. It refuses a different target and
does not repair it. Checks and publication are not atomic against same-UID
interference; no record establishes real rollback or descendant cleanup.
Before publishing a fixture resume observation, the component rechecks the
snapshot against the bytes used to inspect the target and rechecks the target.
A detected change or corruption aborts; the recheck and publication remain
non-atomic and do not protect against same-UID interference.
The synthetic recovery and resume flows read through the same pinned state
directory and compare it with the named directory before mutation or result
publication. A detected replacement aborts even if the replacement has the
same attempt ID and snapshot. These point-in-time comparisons are not atomic
with later operations and are not a same-UID security boundary.
The fixture-only resume observation can be reopened in another process. It
checks both the pending intent and the earlier rollback-record prefix; missing,
partial or inconsistent resume records remain unavailable. This is diagnostic
evidence only and does not authorize another attempt.
The gate can also persist a matching direct-child PID locator after fixture
admission and before release, with a pidfd-based direct-child check. The status
reader recognizes it as pending, never as clean, and no recovery code adopts or
signals the stored PID: PIDs can be reused and the record can be altered by
the same user. The process-exit test does not prove descendant cleanup or
rollback, and does not exercise a real delegated cgroup.
The production `same_user_supervisor` building block now persists an intent
before the caller creates a child, borrows that direct child's handle, records
only its unverified PID locator, and can persist a direct exit after a
nonblocking wait. It cannot spawn, signal, release, or adopt a process, and
never authorizes work. On binding failure the caller retains the child and is
responsible for cleanup. It is not wired to Codex execution; missing cleanup and
rollback guarantees continue to block the provider. Tests with real synthetic
children do not establish process-tree isolation or power-loss durability.
If publishing the direct-child exit fails, the live observer keeps that
failure terminal and does not retry an ambiguous write. The recovery record
remains pending; neither the error nor an eventual absence of the exit record
proves descendant cleanup or rollback.
The component's read-only `inspect_recovery` reopens local evidence and reports
descendant cleanup and rollback separately as unknown. It does not validate an
atomic snapshot, signal a stored PID, perform recovery, or permit an operation.
It distinguishes recorded direct-child success, recorded failure, and
unavailable or inconsistent exit evidence. These observations are local and
unauthenticated; even a successful direct exit does not prove tree cleanup.
It separately reports whether a snapshot envelope could be read and verified;
missing, malformed, inconsistent, or temporarily inaccessible records are
reported together as unavailable or invalid. A valid envelope alone is not a
complete file backup or authenticated provenance.
The Linux `recovery status` CLI exposes the same bounded envelope observation in
both supported languages. Its reads are sequential, may report unavailable
under lock contention, and never authorize recovery or clear the pending state.
The CLI also reports whether direct-child success, failure, or unavailable exit
evidence was observed. It does not infer descendant cleanup from any exit.
`PendingAttempt::store_synthetic_snapshot` and `read_pending_snapshot` provide
an opt-in, bounded create-only byte record linked to the pending intent. The
record is private but **not encrypted** and is for synthetic data only. A
SHA-256 digest detects accidental corruption, not same-UID interference. The
record does not describe files, prove a consistent backup, restore a target,
establish descendant cleanup, or authorize Codex. Incomplete writes remain
pending; no automatic deletion or repair is performed. Tests after process exit
do not establish durability after power loss.
Interruption tests exercise snapshot publication after file creation, after
the header, and after the payload but before sync. Partial records remain
unavailable; a complete-looking envelope after process exit is not proof that
it survived a power failure. Existing records are never overwritten by retry.
An experimental wrapper records presence and synthetic contents for two fixed
names; it can persist and reopen those records without the `codex-fixture`
feature. The synthetic-only restore also works without that feature, and
creates a new temporary directory rather than restoring the original tree.
Under `codex-fixture`, the pending attempt can capture those fixed names from
a disposable TempDir before child binding. Capture refuses symlinks,
non-regular files and files larger than 64 KiB; the sequential reads do not
provide a consistent snapshot against concurrent modification. It is not
connected to real projects or Codex, and its bytes are unencrypted.
The synthetic review gate can own such a source and capture it after persisting
intent and before spawning. Capture errors leave intent pending and block the
child. The gate uses the captured bytes for its later snapshot comparisons;
this remains a fixture, not real provider admission.
Immediately before spawn it also rereads those fixed source files and refuses
a detected change. This read is not atomic with spawn or other writers and
does not establish a consistent production backup.
The fixture repeats the comparison before binding the created direct child;
a detected mismatch closes that gate instance without recording its locator.
The fixture also retains the observed recovery-directory path and compares its
current identity with the pinned descriptor before starting, binding and
release. A detected replacement fails closed. These are point-in-time checks,
not atomic path ownership or protection against same-UID interference.
The same fixture checks the recovery path before and after publishing a direct
child's exit. A mismatch detected beforehand prevents publication; a mismatch
detected afterward can leave an exit record and remains ambiguous.
The same-user direct-child observer likewise retains the original state path
and checks its identity before and after exit publication. A detected mismatch
ends publication attempts for that observer; a late failure may leave a record.
These checks are not atomic and cannot stop same-UID interference.
The same-user binding checks the state path before and after recording the
child locator. Failure returns responsibility for the child to its caller; a
failure after the write can leave a locator in the moved pending state.
The initial intent write likewise checks the observed state path before and
after publication. A detected late replacement returns an error but can leave
the intent in the moved directory; it is never automatically deleted.
For a path-based request the supervisor retains the requested absolute path
(resolving relative paths against the current directory before opening) rather
than adopting a new pathname read from the descriptor after a rename. The gate
passes its previously captured path through to intent creation. These checks
remain non-atomic and cannot prove path stability against same-UID interference.
Its synthetic snapshot and post-image writes also check the named state path
before and after writing. A late mismatch can leave a complete or partial
record; errors do not authorize deleting or retrying against a new directory.
The gate repeats that source comparison before writing its release byte and
permanently closes that gate instance on detected divergence. This does not
prevent a child from running before it cooperatively waits for the byte, nor
does it establish containment against same-UID processes.
Missing metadata and corrupt snapshots are rejected. It
does not capture real filesystem metadata, restore the original tree, verify
cleanup, or establish a production rollback. A process interruption can leave
an incomplete temporary directory, which is not a completed recovery.
The fixture feature additionally contains a one-file rollback drill for an
owned temporary directory. It checks the pending snapshot and an expected
synthetic post-image, refuses symlinks and unexpected lockfiles, and does not
clear the pending attempt. Comparison and replacement are not atomic together;
it is not safe for concurrent writers or real projects and does not verify
descendant cleanup or authorize Codex.
For a synthetic manifest recorded absent, the drill can remove a subsequently
created file only when its observed bytes match the expected fixture bytes.
The comparison and removal are not atomic; failure can occur after removal.
An opt-in fixture can persist expected synthetic post-image bytes before child
binding and reopen them after interruption. The record is bounded, create-only,
linked to the intent and checked with SHA-256, but is unencrypted and not
authenticated. Recovery checks it again before mutation and publication; those
checks are non-atomic. This does not establish that real updates have a known
post-image, or authorize restoring a real project.
The synthetic post-image can also explicitly encode an absent manifest,
distinct from an empty file. The fixture can then restore an originally
present file to a disposable target using no-clobber publication; an
unexpected file is preserved. This is not real-project rollback or proof of
cleanup, and surrounding checks remain non-atomic.
An isolated test interrupts the supervised fixture's file operation before
and after no-clobber publication, then reopens the persisted absent post-image
and retries against the same temporary target. It does not establish
power-loss durability or process-tree cleanup.
New fixture post-image records additionally bind the digest of the validated
snapshot; a missing or different snapshot is refused. Earlier `TUCPOST1`
fixture records cannot establish this binding and are treated as invalid,
preserved without automatic migration or deletion. SHA-256 is not authentication.
One-file and two-file post-images now carry distinct fixture format tags and
cannot be consumed by the other recovery flow. The earlier `TUCPOST2` tag did
not distinguish the modes; those records are also rejected and preserved, not
automatically migrated or deleted. New tags do not authenticate records.
The current fixture format also includes the mode tag and encoded length in the
digest, distinguishing absent from empty content under accidental corruption.
The earlier `TUCSING1` and `TUCMULT1` records lack that coverage and are refused
without deletion or automatic migration. Digests remain forgeable by the same UID.
An interruption drill covers post-image creation, header and payload writes.
Incomplete records remain invalid and cannot be overwritten by retry. A complete
record observed before sync after process exit is not proof of power-loss durability.
The synthetic review gate can persist this post-image along with a captured
source before spawning, and rechecks it before fixture child creation, binding
and release. The comparisons are point-in-time observations only.
The gate can also encode an explicitly absent synthetic post-image; a valid
empty-file record is not equivalent. After the synthetic supervisor exits,
the fixture restores an originally present file only into a disposable target.
A fixture test interrupts a supervised synthetic process immediately after
removal and resumes against the same disposable directory while leaving the
attempt pending. Process exit does not demonstrate power-loss durability or
prove descendant cleanup.
An additional fixture-only two-file drill persists expected states of both
fixed synthetic names in the bounded post-image. It preflights both files,
restores each separately, and writes a separate create-only two-file observation
only after checking both. Interruption between files can leave a partial result;
retry accepts only files matching their recorded original or expected state.
The operations and checks are not a transaction or a same-UID security boundary,
and cannot be used to restore real projects or authorize Codex.
The two-file fixture result can be reopened as a bounded local observation
linked to the pending intent, snapshot digest and typed post-image digest.
Its resume observation carries the same bindings. Older multi-result and
multi-resume v1 records lack these bindings and are rejected without automatic
deletion or migration. Digests do not authenticate same-UID state.
The multi-resume v3 observation additionally binds the exact prior rollback
record, including a partial prefix. Older multi-resume v2 records are rejected
and preserved, without migration. A matching digest does not authenticate data.
Before creating either result, publication compares the exact snapshot and
post-image bytes used by the operation with the current validated plan under
the cooperative write lock. Non-cooperating same-UID writers can still race it.
Publication derives its result digests from the verified bytes rather than a
second plan read. A detected later mismatch makes the observation invalid; a
completed write does not prove that the plan or target remained unchanged.
Tests interrupt result publication after creation
and after writing but before sync: a partial record is invalid, and even a
complete-looking record is not proof of power-loss durability. Both preserve
the pending attempt and refuse duplicate recovery.
When the two-file result publication fails, a fixture-only resume can observe
that both disposable targets match the original snapshot and write a separate
create-only observation, preserving the prior result and pending intent. A
divergent target is not repaired. These checks and publication are non-atomic;
neither record proves production rollback, cleanup, or power-loss durability.
An interruption test also stops publication of that resume record immediately
after creation and after writing but before sync. A partial record is invalid;
a complete-looking record is only an observation, and neither permits retry or
clears the pending intent.
The synthetic review gate accepts a bounded structured two-file post-image
and persists it before child creation. A fixture test interrupts recovery
between the files, rejects a conflict on retry, and completes a later retry on
the same disposable target without clearing the pending intent. The test does
not prove process-tree cleanup or establish production recovery safety.
The drill pins the target directory and checks its identity before and after
replacement. A detected directory replacement is refused; a failure after the
file replacement may still mean the target changed. Checks remain non-atomic
and are not protection against same-UID interference.
The integrated drill rechecks its pinned state directory and snapshot after
the file replacement and checks the synthetic target content before publishing
a result. A detected change leaves the result unpublished, but cannot undo an
already completed replacement. These checks are not atomic with publication.
Single-file fixture rollback and resume observations bind the snapshot digest;
resume also binds the exact prior rollback record. When a typed post-image is
part of the plan, v3 observations bind its presence or absence and contents.
Snapshot-only v2 observations remain valid only when no post-image record is
present; incompatible older observations are rejected and preserved without
automatic migration. Digests do not authenticate against the same UID.
An orphaned or partial single-file resume record blocks starting either fixture
rollback mode. Result publication also rejects detected conflicting records;
the checks are advisory and do not remove or repair any of them.
The fixture rechecks pending result conflicts before the single-file mutation
and before each two-file step. A conflict between two files leaves a partial
rollback; these point-in-time checks are not atomic with later mutations.
The read-only fixture observers also reject detected records from the other
mode, including partial records; they do not infer a clean or recovered state.
For the integrated synthetic same-user journey, waiting for the direct child
also writes a create-only exit observation. It is read after restart only when
consistent with the pending intent and one binding; malformed or conflicting
records stay blocked. A direct-child exit, even successful, is not descendant
cleanup or rollback. If publication fails the exit result remains ambiguous.
Synthetic process-exit tests also interrupt this publication after file
creation and after writing but before sync. The first leaves an invalid record;
the second can be observed as a complete record after process exit, but neither
case proves power-loss durability or permits a retry that replaces the file.
The feature-gated review supervisor also attempts to record a direct-child
exit during cancellation, including best-effort fallback after a failed group
stop. It preserves the cancellation error and never infers descendant cleanup
or rollback from that record. This is not production supervision.
An existing pending-attempt path, even a malformed file or dangling symlink,
also prevents creation of a new intent. The same-user intent writer and the
create-only binding writer now take a nonblocking advisory lock on an opened
directory, and binding requires a matching intent. The lock serializes only
writers that participate: direct writes, replacement and interference by the
same UID remain possible. A partial binding remains blocked and must not be
removed automatically. These primitives are not wired to production execution.

Status: **same-user supervision selected; not implemented or approved for enabling a provider**.
The existing Codex recovery gate remains blocked. This note preserves the
earlier independent-authority investigation as historical context; it does
not select a privileged daemon, request new privileges, or authorize deployment.

## Threat model and observations

### Revised decision: same-user supervision

The user rejected a system service and additional operating-system account and
accepted supervision under the interactive user, with the explicit limitation
that it does not protect against malicious processes running under the same
UID. This supersedes the earlier independent-authority direction below; the
earlier discussion is retained as historical context, not an activation gate
requiring a new system account. Same-UID processes, including a workload if it
runs under that UID, may interfere with the supervisor or its records. Do not
claim otherwise or describe a same-user journal as tamper-proof.

This decision concerns the design direction only. It does not approve provider
activation, running real upgrades, changing privileges, or installing services.
The present production Codex gate stays blocked until an implementation for
ordinary failures and usable recovery is verified and activation is separately
approved. Cancellation, direct-child exit, descendant cleanup, rollback, and
recovery remain distinct; unknown outcomes must not be silently marked clean.
Determine what process-tree containment and crash recovery the target host can
actually provide without a dedicated account or privilege changes before
claiming either guarantee. No such guarantee is established by fixture tests.

### Historical independent-authority proposal

The review workload and its descendants are less trusted than the supervisor.
They must not be able to impersonate the authority, change its durable registry,
invoke its manager operations, or obtain the credentials used by the application.
**Threat-model decision:** the user confirmed that unrelated processes running
under the same UID must be treated as adversarial. A user-owned bus, directory,
or signing key alone is therefore not an independent root of trust. Root/kernel
compromise remains outside this proposal; neither that exclusion nor a different
UID by itself proves isolation.

This decision does not approve a particular authority, service identity,
privilege model, installation, deployment, or a blanket change to existing
operation availability. Those choices remain open. Until an independently
authenticated authority and its guarantees are implemented and verified,
same-UID observations and retained backup files must not be used as proof of
ownership, clean state, or authorization to recover or enable a provider.

The user selected work toward an independent authority and a usable recovery
journey together. Local synthetic development is authorized; installation,
privilege changes, and activation still require a separate impact explanation
and approval. The feature-gated `authority_lifecycle_fixture` module models
ordering and fail-closed restart behavior only. It provides no authenticated
authority, durable storage, OS isolation, or permission to launch real work.
Its synthetic recovery projection distinguishes an unavailable authority,
unprovisioned state, an observation without pending work, a pending attempt,
and recovery required. Incomplete attempts retain their synthetic attempt and,
when known, incarnation IDs across the model's restart transition. The
projection is not connected to the UI, does not authenticate observations, and
does not offer automatic restore or unlock.
The fixture diagnostic separates a recorded phase from unverified execution,
descendant cleanup, and rollback outcomes. New synthetic interruption records
retain their prior recorded phase; older records lack it and the diagnostic
reports it as unknown rather than inferring it from an incarnation identifier.
Neither the phase nor any other same-UID-mutable journal data is authenticated.
The diagnostic separately records the gate outcome as unknown: recording a
release before the callback does not prove whether the callback took effect.
A synthetic callback may produce an effect and still return an error; retry is
blocked and the record remains pending recovery.
The synthetic status response carries this optional phase to its diagnostic;
legacy records and legacy response frames without the field remain unknown.
The public fixture reader still rejects all unauthenticated responses.
An in-process fixture diagnostic reads the journal afresh and does not authorize
recovery. A test reopens the synthetic server in separate child processes and
checks that the persisted interruption is not reconciled twice; this is not a
power-loss, independent-UID, process-cleanup, or production-service test.
The journal reader and frame decoder reject contradictory phase/identity shapes;
this detects only structural inconsistencies, not forged but consistent data.
The feature-gated `authority_journal_fixture` explores explicit initialization,
bounded decoding, file sync followed by rename and directory sync, and an
ambiguous failure after rename. Its version comparison assumes a single writer
and is not an atomic cross-process compare-and-swap. The directory, records and
IDs remain same-UID mutable and unauthenticated; no rollback protection, secure
provisioning, production persistence or authority is supplied by this fixture.
Fault injection and process-exit tests do not demonstrate power-loss durability.
The fixture journal also provides an explicit single-writer startup step that
persists an incomplete intent, binding, or release as recovery-required before
returning it. Failed publication remains an error, including after rename;
reopening a persisted recovery record is idempotent. This step is not wired to
a service and does not verify process cleanup, authenticate a record, or make a
stored ready state trustworthy.
`SyntheticServer::open` performs that startup step once before the fixture
server can handle queries; an error prevents server construction. Subsequent
queries remain read-only. A nonblocking advisory file lock prevents two
cooperating synthetic servers, coordinator callbacks and public journal writes
from operating simultaneously against the same lock inode. It does not prevent
uncooperative file writes, same-UID replacement or bypass, and
does not protect the path, authenticate clients, or reconcile real processes.
Initialization remains a separate explicit create-only operation, and the
journal still assumes no writer bypasses the lock. The coordinator
releases its lock between steps, so a server may reconcile an incomplete attempt
between them; subsequent coordinator operations then fail closed.
Internal locked journal operations require a live cooperative guard for the
same supplied directory path. They also compare pinned directory and lock inode
metadata against the names at selected points; the server checks after reading
a request and again before replying, or before returning a local diagnostic.
These are best-effort fixture checks, not an
atomic path binding or protection against path races and hostile same-UID
processes. An error after rename has an ambiguous publication outcome.
A protocol test bypasses the peer check solely to
exercise the recovered projection.
The feature-gated `authority_coordinator_fixture` connects this journal to
synthetic creation and gate callbacks. It records intent before invoking the
creation callback and release before invoking the gate callback; duplicate or
ambiguous attempts do not automatically invoke either callback again. This
assumes a single writer and does not establish ownership of an actual unit,
protect the journal, authenticate requests, or authorize real operations.
The feature-gated `authority_service_fixture` composes that coordinator with
an explicitly supplied synthetic direct child and a one-byte stdin gate. Its
test uses a harmless, isolated child: failures before or after journal rename
leave recovery pending, and the gate byte is attempted only after the release
record is published. A failed gate write may have an ambiguous outcome.
It now opens a pidfd and checks nonblocking `waitid(P_PIDFD, WNOWAIT)` for a
live direct child after intent and before binding, and rechecks before release
and before the gate write. This is a momentary parent-child check only; the
persisted incarnation is still caller-supplied and cannot authenticate or bind
that process after restart. The child can exit between checks.
Direct-child cleanup on error is best effort; there is no bounded drain,
descendant tracking, sandbox, authenticated ownership, or crash recovery
guarantee. This fixture must never launch production work or enable Codex.
When its direct child is reaped, the fixture attempts to persist the observed
success/failure before returning. Publication errors remain errors, including
ambiguous post-rename failures; restarting still marks the attempt as recovery
required. A recorded direct-child exit does not establish descendant cleanup,
rollback, durable authority, or permission to start another real operation.
The feature-gated `authority_transport_fixture` experiments with bounded local
response frames and kernel peer credentials. It rejects same-UID peers before
reading and rejects even a well-formed response because independent authority
authentication is not implemented. It is not a production protocol or server;
UID matching alone cannot authenticate the executable, bind an authority
generation, distinguish same-UID callers, or authorize any operation. Its
single-connection read-only synthetic server loads the fixture journal only
after its experimental peer-UID filter; all mutation commands are absent. The
protocol-plumbing test bypasses peer verification deliberately, and no
cross-UID positive connection has been verified. The fixture status reader
still rejects all responses as unauthenticated.

The Linux production `authority_probe` module can inspect kernel peer
credentials on an already-connected Unix socket without exchanging data. Its
only result is `Unknown`: an absent socket, unavailable credentials, same-UID
peer, or different but unverified identity never permits an operation. No
connector, endpoint provisioning, expected authority identity, authenticated
status protocol, or UI integration is implemented. A different UID or UID 0
is not treated as proof of authority.
It also provides a read-only Linux directory screening function using anchored
`openat` operations and no-follow flags, checking each opened directory's owner
and basic mode. It always returns unknown and is not wired to admission. ACLs,
mounts, user namespaces, path replacement and authority identity are not proven;
a passing screen is not protected storage or independent authentication.
Its anchored component walker is tested against isolated synthetic directories,
ordinary files, symbolic links, parent traversal and writable directory modes;
the tests use a synthetic owner and do not prove a root-owned deployment.
The separate socket metadata probe opens a name relative to a supplied directory
descriptor with `O_PATH | O_NOFOLLOW`, checks basic file type, owner and mode,
and never connects. The directory descriptor is not authenticated by this
probe. Successful metadata checks remain `Unknown` and cannot establish socket
ownership, peer identity, protection against replacement, or authorize work.
The production endpoint probe combines the directory walker with the socket
metadata check via the final pinned directory descriptor, without connecting.
This reduces pathname re-resolution but does not prove ACLs, trusted mounts,
provisioning, peer ownership, or future pathname identity; it always returns
unknown. A synthetic rename test exercises descriptor anchoring, not authority.
The Linux `authority_store` module supplies record-screening and an explicit
create-only pending-record building block. It opens a fixed name relative to a supplied directory fd,
rejects symlinks, non-regular and multiply linked records, checks basic owner
and mode, bounds its read and validates a minimal pending-record schema. All
outcomes remain unknown. The format is experimental, not a provisioned store;
the module does not prove directory provenance, ACLs, mount isolation, record
freshness or authenticity, and is not connected to service admission.
The create-only primitive is not automatic provisioning: it refuses existing
files and leaves partial or completed records in place on failure. Sync calls
and injected errors are not evidence of power-loss durability, protected
storage, or authorization to start a workload.
The Linux `authority_supervision` module combines the blocked record
observation with a nonblocking direct-child `pidfd` exit observation. It sends
no signals and never permits an operation. The two observations are not bound
to each other: obtaining a pidfd from a numeric PID does not establish authority
ownership or rule out earlier PID reuse, and neither exit nor lack of an exit
event proves descendant cleanup, isolation, or rollback. Synthetic tests do not
establish an independent production supervisor.
The production `authority_core` composes explicit create-only pending-record
persistence with the direct-child observation, but does not establish any
relationship between the record and process. It has no spawn, release, stop,
clear or unlock operation. Its mutating method must not be exposed through IPC
before independent authorization and provisioning are designed and verified;
that method is not connected to the CLI's read-only status or Codex admission.
Tests use a synthetic owner and child and do not prove independent authority.
`stage_observed_pending` additionally returns a process-local quarantined handle
containing caller-supplied IDs and a pidfd acquired after the pending write.
Before returning it now uses nonblocking `waitid(P_PIDFD, WNOWAIT)` to reject
exited or non-child processes at that instant, without reaping them. This check
is local to the calling process and does not authenticate the service, record,
or full process incarnation. Failure leaves the pending record untouched.
The caller supplies an already-existing child: this does not enforce intent
before process creation, establish provenance, bind a persisted incarnation,
or provide recovery across restart. If pidfd acquisition fails, the pending
record remains. The handle cannot authorize, spawn, release, or clear work.
An explicit create-only binding operation can record the matching pending IDs
and a PID locator after a local direct-child check. The PID is not an identity
or adoption proof, the journal is not authenticated, and an error may leave a
partial or complete binding. Subsequent checks cannot make this durable
association trustworthy or authorize recovery; no binding is automatically
read, adopted, cleared, or exposed to IPC.
An explicit local diagnostic can compare the pending and binding files with a
direct-child pidfd and `SO_PEERCRED` on an already-connected Unix socket. It
also requires `SO_PEERPIDFD`, a close-on-exec peer pidfd and a nonblocking
direct-child check. Unsupported kernels or missing evidence fail closed. A
match is labelled *consistent but unauthenticated* and always remains blocked.
The diagnostic opens the binding file using `openat2` with beneath, no-symlink,
no-magic-link and no-mount-crossing resolution. Unsupported kernels fail closed
without a weaker fallback. The pending record reader is unchanged; these checks
do not authenticate the supplied base directory or protect an inode's contents.
Records can be forged, PIDs and namespaces can be misleading, socket fds can be
passed to another process, and checks are not atomic; neither matching kernel
metadata nor these tests establishes an independent trust boundary.
The quarantined attempt can separately inspect a nonblocking datagram with
per-message kernel credentials against its locally observed direct child. A
match remains unauthenticated, does not verify a persistent binding, and never
authorizes work. Missing, invalid, truncated or mismatched messages are rejected;
SCM_RIGHTS descriptors delivered to the process are closed. This is not a
production identity protocol or proof of exclusive socket ownership.
An additional diagnostic compares this per-message observation with the
untrusted pending and binding files. These are separate, non-atomic checks:
even a consistent result does not establish protected storage, authentication,
or a binding usable after restart.
`authority_identity` compares a connected peer's `SO_PEERCRED` UID to a
supplied workload UID and store-directory owner/mode and combines that with the
blocked record observation. It additionally requires an unexited peer pidfd
obtained via `SO_PEERPIDFD`; an unavailable pidfd remains blocked. This does not
require the peer to be a direct child. All supplied identities and the directory origin
remain untrusted. A candidate match is always unauthenticated and never permits
work. Tests using an invented workload UID do not demonstrate cross-UID
isolation or protected persistence.
The quarantined-attempt diagnostic can derive the workload UID from its socket
and combine it with identity/storage and binding observations. A sandbox test
uses real same-UID sockets and confirms that even a matching local process and
record cannot authorize work. Socket passing and untrusted directory provenance
still prevent treating these combined observations as authentication.
The `tucupi-authority status <directory>` executable exposes a read-only,
localized blocked diagnostic; it neither authenticates the path nor starts a
service. With `codex-fixture`, `fixture-status` additionally starts one fixed
synthetic child and compares direct-child observations before and after exit.
It does not write records, create units, prove ownership or cleanup, or enable
Codex. Run the synthetic path only in an isolated test environment; its
successful exit means only the diagnostic completed.
With the feature enabled, the separate `fixture-attempt` command mutates only
an explicitly initialized fixture journal, starts the fixed synthetic gated
child, records its direct-child exit, and marks recovery required. It refuses a
duplicate against pending recovery and does not clear the record. It must be
run only with disposable isolated fixtures; the production build rejects it.
It is not an independent service, protected registry, or descendant supervisor.
With the fixture feature, `fixture-user-attempt <journal> <recovery>` exercises
the same-user intent and synthetic binding in two explicitly supplied disposable
directories. The real `recovery status` command can inspect those records after
the fixture process exits, but does not authenticate their synthetic unit IDs,
prove cleanup, restore a backup, or permit another operation. This command is
not available in the default build and must not target real recovery state.

### Isolated validation

In the local `bwrap` sandbox the repository and toolchain are read-only,
external networking is isolated, and the writable build tree is bounded tmpfs.
The focused probe tests, formatting check, Clippy and documentation tests ran
there. With public CA certificates mounted read-only, the full suite passed
both serially and in parallel with `TOKIO_WORKER_THREADS=2` and a 128-process
limit. Without that Tokio bound a parallel run timed out in CLI tests; the exact
underlying cause remains unproven, though bounded workers avoided it. The
isolated namespace allowed a local TCP connection even though bringing its
loopback interface up explicitly was denied. No host network or elevated
privileges were used. These tests do not validate a production authority.

`tests/codex_fake_manager_bus_fixture.py` demonstrates that a private same-UID
bus and fake manager can produce matching diagnostic data when selected as the
runtime. The default flow ignores the tested bus environment overrides, but this
does not authenticate its fixed socket or prevent same-UID state substitution.
`tests/codex_systemd_escape_fixture.py` demonstrates that stopping a unit does
not reach a process already moved to another unit. These tests are evidence of
limitations, not implementations of the proposed authority.

## Historical proposal: independent authority

### Candidate deployment model — not approved

One possible Linux deployment is a system-managed authority running under a
dedicated service account distinct from the interactive user and the workload.
An administrator would explicitly provision a private registry owned by that
account, a separately controlled local IPC endpoint, and a narrowly scoped
supervision mechanism. The authority, not the caller, would create gated work
after recording intent. Client requests would require an explicitly designed
authorization policy; a UID check alone is insufficient. The service account
must not be able to access the user's Codex credentials by default.

This is a proposal, not an installation recipe or a security guarantee. A
separate UID and file modes alone do not establish protection from ACLs,
descriptor sharing, namespace confusion, privileged administrators, manager
API escape, registry rollback, or filesystem failure. In particular a local
file and `fsync` cannot by themselves detect an administrator restoring an
older copy. Define the rollback adversary and an independent freshness anchor
or explicitly accept that this requirement is unmet; unknown stays blocked.

Before implementation selects this model, decide whether a system-level
service and dedicated identity are acceptable and which actors are trusted
administrators. A later installation would change system accounts, files,
service management and access policy, and requires a separate proposal and
explicit approval; no such change is made by this document. Recovery must
preserve unknown records, verify ownership and descendant cleanup, and require
an explicit operator decision rather than deleting state to unblock Codex.

Any future authority must have OS-enforced identity and storage isolation from
the workload under the chosen threat model, with authenticated, authorized and
bounded local IPC. Its provisioning, execution identity, administrative access,
and lifecycle remain open decisions. A service using the same credentials and
mutable state as its adversary is not independent merely because it is another
process. An application-generated UUID, matching unit name, D-Bus peer UID,
`ProcessFD`, or signature whose key is accessible to the workload is not proof
that this authority created the unit.

The authority—not the workload or an untrusted caller—must control creation and
bind one immutable attempt identity and policy snapshot to the exact supervised
unit incarnation and its own durable registry. Its authenticated status must
bind that record to the same unit and authority generation. App and batch must
consult the same authority and preserve pending/unknown states across restarts.
Installation and initial provisioning must be explicit. Missing, replaced,
corrupt, rolled-back, incomplete, or unavailable state must not imply clean.

Persist an intent before any unit or workload can be started; durably record
the exact created incarnation before releasing execution. Crashes between those
steps must leave a recoverable *unknown* attempt, not a clean one. Handle lost
replies and duplicate requests without creating a second uncontrolled unit.
Never automatically adopt a matching name as proof of creation. A completion
record must not be promoted until authenticated ownership, effective isolation,
and cleanup of all admitted work have been established; a single empty-cgroup
observation is insufficient. No present implementation satisfies these rules.

## Historical independent-authority evidence requirements

1. Demonstrate the authority and registry cannot be impersonated, modified,
   replaced, replayed, or rolled back by the workload and by other actors covered
   by the chosen threat model. Test unavailable authority and first provisioning.
2. Exercise real creation and registry binding with synthetic work; inject crashes
   before and after durable intent, unit creation, binding, release and response.
   Restart both App and batch and verify no unknown attempt is accepted as clean.
3. Exercise stale/replaced units, manager or authority restart, forged matching
   records, duplicate and concurrent requests, escaped processes, repopulation,
   and incomplete cleanup. Verify no result promotion or automatic unlock.
4. Validate OS-enforced filesystem, descriptor, manager API, network and
   credential boundaries independently; document unsupported hosts and failures.
5. Review the authority's privilege surface, recovery and explicit unlock
   procedure, and obtain the required operator decision before any installation
   or activation. Apple validation requires a compatible Mac and is separate.

The tests above are acceptance requirements, **not claims of passed tests**.

## Isolated lifecycle experiment

`TMPDIR=... /usr/bin/python3 tests/codex_authority_lifecycle_fixture.py`
exercises a same-user test controller with uniquely named transient services.
It syncs a synthetic intent before unit creation, records the unit invocation,
and abruptly exits after intent, creation, or binding. A separate process keeps
each state blocked; duplicate intent and a mismatched binding are rejected.
The harness stops only its verified synthetic service. This checks selected
ordering and process-crash behavior, not power-loss durability. The controller
and its registry are writable by the same user, the unit is an ordinary sleep
process (not a gated review workload), and the binding is not authenticated.
No independent trust boundary, supervisor IPC, release gate, production
recovery, or safe cleanup/unlock is implemented by this experiment.

`TMPDIR=... /usr/bin/python3 tests/impact_durable_binding_fixture.py` applies
the same synthetic journal to the actual impact-preview runner: an intent is
synced before creating a uniquely named transient unit, then its observed
invocation is synced before a benign fixture gate is released. A separate
process checks that interruption after intent, creation, or binding remains
blocked and duplicate admission is rejected. After creation without binding,
the fixture worker reaches the gate but does not start its synthetic descendant.
The gate is a same-user-writable file and is not an isolation or authorization
boundary; the registry is unauthenticated and its data can be replaced. The
experiment uses process exits, not power-loss or manager-restart simulation,
and does not implement production cleanup, recovery or a shared App/batch gate.
