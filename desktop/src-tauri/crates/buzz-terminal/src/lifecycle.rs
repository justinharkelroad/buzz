//! Child-process lifecycle for spawned PTY sessions.
//!
//! Closing a terminal tab must actually end the work the tab was doing. That
//! is harder than calling `kill`, for two reasons that both come from the
//! child being a *session leader* rather than an ordinary subprocess.
//!
//! **1. The child is not the only process.** `portable-pty` calls `setsid()`
//! in `pre_exec` (`unix.rs:257`), so the shell becomes a session and process
//! group leader; everything it runs — `vim`, a `make -j8` tree, a backgrounded
//! `sleep` — joins that group or a descendant of it. Signalling the shell's
//! pid alone reaches the shell. A shell that exits without forwarding the
//! signal leaves its children running, reparented to init, holding the pty
//! slave open. That is a leak that survives the window closing.
//!
//! So we signal the **process group** (`kill(-pgid)`), not the pid.
//!
//! **2. `portable-pty`'s own `kill` is not sufficient here.** `ChildKiller for
//! std::process::Child` (`lib.rs:340-373`) sends `SIGHUP` to the *pid*, waits
//! up to 4x50 ms, then falls back to `Child::kill` — which is `SIGKILL`, again
//! to the pid. Both halves are pid-scoped, so neither reaches a grandchild.
//! It is a correct API for "end this process"; ours is "end this session".
//!
//! ## The escalation
//!
//! `SIGTERM` to the group, a bounded wait for the leader, then `SIGKILL` to
//! the group **whether or not the leader went quietly** -- see `shutdown` for
//! why a polite leader does not imply an empty group.
//! `SIGTERM` first because a shell asked to terminate cleanly will flush its
//! history and let `vim` write its swap file; going straight to `SIGKILL`
//! guarantees no process ever gets that chance. The bounded wait is what makes
//! the escalation real — without it, `SIGKILL` either races the polite path
//! (making `SIGTERM` decorative) or never fires (making a signal-ignoring
//! child immortal).
//!
//! ## What this deliberately does not do
//!
//! A process that has called `setsid()` for *itself* has left our group, and
//! no group signal reaches it. `nohup`, a daemonising build tool, and
//! `tmux`-style servers all do this on purpose. We do not hunt the process
//! tree to find them: walking children to signal them is a race against a
//! moving tree — a pid read and then signalled may be a *different* process by
//! the time the signal lands, and killing a stranger's pid is a far worse bug
//! than leaking a daemon the user deliberately detached. Detaching from the
//! session is the documented way to survive one's terminal, and honouring it
//! is correct behaviour, not a gap.

use std::io;
use std::time::{Duration, Instant};

use portable_pty::Child;
#[cfg(unix)]
use rustix::process::{
    kill_process, kill_process_group, waitid, Pid, Signal, WaitId, WaitIdOptions,
};

/// How long the group gets to honour `SIGTERM` before `SIGKILL`.
///
/// Long enough for a shell to run its exit trap and for an editor to write a
/// swap file; short enough that closing a tab never feels stuck. Tab close is
/// not synchronous with this wait in the UI, so this is a cleanup deadline,
/// not a frame budget.
pub const TERM_GRACE: Duration = Duration::from_millis(250);

/// Poll interval while waiting for the child to exit.
///
/// Polling rather than blocking in `wait()`: a blocking wait cannot be given a
/// deadline without a second thread, and the whole point of the grace period
/// is that it expires.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// How a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shutdown {
    /// Already gone before we signalled.
    AlreadyExited,
    /// Exited within [`TERM_GRACE`] of `SIGTERM`.
    Terminated,
    /// Ignored or outlived `SIGTERM`; the group was killed.
    Killed,
}

/// Ends the session led by `child`: `SIGTERM` to its process group, a bounded
/// wait, then `SIGKILL` to the group if anything is still there.
///
/// Reaps the child before returning, so the caller cannot leave a zombie by
/// dropping the handle. Returns which arm ended it, which is what a test can
/// assert on — "did it die" is satisfied by both arms and so distinguishes
/// nothing.
#[cfg(unix)]
pub fn shutdown(child: &mut Box<dyn Child + Send + Sync>) -> io::Result<Shutdown> {
    let Some(raw_pid) = child.process_id() else {
        // No pid means nothing to signal; still ensure it is reaped.
        child.wait()?;
        return Ok(Shutdown::AlreadyExited);
    };
    let raw_pid = i32::try_from(raw_pid).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "PTY child returned a process id outside the platform pid range",
        )
    })?;
    let Some(pid) = Pid::from_raw(raw_pid) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PTY child returned process id zero",
        ));
    };

    // Inspect without reaping. An exited-but-unreaped leader is the safe
    // anchor for its numeric process-group id: while the zombie exists, the
    // kernel cannot recycle that pid for an unrelated group. Calling
    // `try_wait` first destroys that anchor and, worse, returns before killing
    // descendants that still hold the PTY slave open.
    let leader_already_exited = match leader_exited(pid) {
        Ok(exited) => exited,
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::CHILD.raw_os_error()) => {
            // `ECHILD` means some earlier owner already reaped this handle.
            // In that case its saved numeric pid is no longer safe to signal.
            if child.try_wait()?.is_some() {
                return Ok(Shutdown::AlreadyExited);
            }
            false
        }
        // We still hold the unreaped child handle, so a transient observation
        // error does not invalidate the process-group id. Continue with the
        // bounded signal/reap path instead of reaping before the group sweep.
        Err(_) => false,
    };

    signal_group(pid, Signal::TERM);
    let leader_honoured_term =
        leader_already_exited || leader_exited_by(pid, Instant::now() + TERM_GRACE);

    // Sweep the group unconditionally, *including* when the leader exited
    // politely. The leader's exit is not the session's end: anything it
    // backgrounded that ignores SIGTERM is still running, still in the group,
    // and still holding the pty. Returning `Terminated` at that point reports
    // success over a leak.
    //
    // Ordering with the reap is a safety requirement, not a preference. A
    // process group id *is* the leader's pid, and the kernel may recycle that
    // pid once the leader is reaped -- at which point `kill(-pid)` names some
    // unrelated group. An exited-but-unreaped leader is a zombie, and a zombie
    // is still a group member, so the id cannot be reused while we hold it.
    // Signal first, reap second, and the window does not exist.
    signal_group(pid, Signal::KILL);

    // SIGKILL cannot be caught, so this terminates. It is still a `wait`
    // rather than an assumption: the pid must be reaped, and the exit status
    // is only available to whoever reaps it.
    child.wait()?;

    Ok(if leader_already_exited {
        Shutdown::AlreadyExited
    } else if leader_honoured_term {
        Shutdown::Terminated
    } else {
        Shutdown::Killed
    })
}

/// Sends `signal` to `pid`'s process group, falling back to the pid alone.
///
/// The fallback matters: `kill(-pgid)` requires the child to *be* a group
/// leader, which it is only because `portable-pty` called `setsid()`. If that
/// ever stops being true, a pid-scoped signal still ends the shell — degraded
/// (grandchildren survive) rather than a silent no-op.
///
/// Errors are deliberately not propagated. Every failure mode here means the
/// process is already gone (`ESRCH`) or was never ours to signal (`EPERM`),
/// and in both cases the following `wait` is the authority on what happened.
#[cfg(unix)]
fn signal_group(pid: Pid, signal: Signal) {
    if kill_process_group(pid, signal).is_err() {
        let _ = kill_process(pid, signal);
    }
}

/// Whether the leader has exited, without reaping it or releasing its pid.
#[cfg(unix)]
fn leader_exited(pid: Pid) -> io::Result<bool> {
    waitid(
        WaitId::Pid(pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    )
    .map(|status| status.is_some())
    .map_err(io::Error::from)
}

/// Polls until the leader has exited, or `deadline` passes. Returns whether it
/// exited in time.
///
/// Deliberately **not** `Child::try_wait`, which reaps: reaping here would
/// release the process group id before the sweep above can use it. `WNOWAIT`
/// reads the child's exit state and leaves it waitable, so the zombie stays
/// and keeps the group id reserved for us.
///
/// `waitid`, not `waitpid`, and that is a portability requirement rather than
/// taste. POSIX only defines `WNOWAIT` for `waitid`; Linux tolerates it on
/// `waitpid`, and **Darwin returns `EINVAL`**. Measured with a C probe: on
/// macOS 25.5.0, `waitpid(pid, &st, WNOHANG | WNOWAIT)` is `-1/EINVAL` for a
/// child that has plainly exited. That failure is silent in the shape this
/// function had — an error is indistinguishable from "not exited yet", so the
/// grace period could never be honoured and *every* shutdown escalated to
/// `SIGKILL`, reporting `Killed` for a child that died politely on the first
/// `SIGTERM`. The polite arm was dead code on the platform we develop on.
#[cfg(unix)]
fn leader_exited_by(pid: Pid, deadline: Instant) -> bool {
    loop {
        let exited = matches!(leader_exited(pid), Ok(true));
        if exited {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

/// Maximum concurrent terminal sessions.
///
/// Each session costs a pty pair (two fds), a reader thread, and a scrollback
/// grid -- at the default 10k lines x 80 cols that is megabytes of resident
/// memory per tab. The cap exists because tab creation is one keystroke and
/// nothing else bounds it: without a limit, a held-down shortcut exhausts the
/// process fd table, and the first thing to fail is not the terminal but
/// whatever *else* in Buzz next asks for a file descriptor -- the relay
/// socket, a database handle. A resource a UI can allocate in a loop needs a
/// ceiling that fails in its own subsystem.
///
/// 20 matches the abandoned `feat/terminal` branch's `MAX_LIVE_SESSIONS`,
/// kept deliberately: it is far above any plausible human tab count and far
/// below the default 256-fd soft limit, so it bounds the runaway case without
/// ever being reachable by hand.
pub const MAX_LIVE_SESSIONS: usize = 20;

/// A reader that is still consuming the PTY master, to be stopped only after
/// the session has been torn down.
///
/// This exists because the correct close order is not the obvious one, and
/// nothing in the type system otherwise prevents the wrong one. Mari's ruling
/// (`62509b91`) is that **the reader outlives child termination and reap**:
///
/// 1. mark the session closing and stop publishing to the UI;
/// 2. `SIGTERM` -> grace -> `SIGKILL` -> reap, *while output is still drained*;
/// 3. only then close the master and join the reader.
///
/// Inverting steps 2 and 3 is the bug this trait is shaped to prevent, and it
/// is not a hypothetical: a child blocked writing into a master nobody reads
/// does not die promptly even on `SIGKILL`, because the kernel completes the
/// tty teardown first. Measured with a `forkpty` probe -- **606 ms** to reap a
/// `SIGKILL`ed child against an undrained master, versus microseconds when
/// drained. Join the reader first and every tab close pays that, on the arm
/// where the user is already waiting.
pub trait DrainingReader {
    /// Detach parser work and enter raw-drain mode before child termination.
    fn begin_closing(&self);

    /// Wake a reader that remains blocked after the child has been reaped.
    fn stop(&self);

    /// Releases the reader thread. Called only after [`DrainingReader::stop`].
    fn join(self: Box<Self>);
}

/// Ends a session in the order the drain law requires, and returns how it
/// ended.
///
/// The ordering is enforced by ownership rather than by documentation: this
/// function takes the reader **by value**, so a caller cannot have joined it
/// beforehand -- a joined reader has been consumed and cannot be passed here.
/// The only way to use this API is the correct order. A comment saying "do not
/// join the reader first" is advice; a moved value is a compile error.
#[cfg(unix)]
pub fn shutdown_draining(
    child: &mut Box<dyn Child + Send + Sync>,
    reader: Box<dyn DrainingReader>,
) -> io::Result<Shutdown> {
    reader.begin_closing();
    // Terminate and reap with the reader still running, so the child never
    // blocks in a tty write while we are waiting on it.
    let outcome = shutdown(child);
    // Unconditional: wake and release the reader whether or not shutdown
    // reported an error. EOF may already have ended it; stop is idempotent.
    reader.stop();
    reader.join();
    outcome
}
