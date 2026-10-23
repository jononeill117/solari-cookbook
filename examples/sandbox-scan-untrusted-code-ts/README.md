# Sandbox: scan untrusted code (TypeScript)

Run untrusted code in a fresh microVM and see what it tried to do — every file
open, network connection, and subprocess — using a Python audit hook
(`sys.addaudithook`, built into 3.8+), so there's nothing to install in the VM.

The hook is a gate, not just a camera: raising inside an audit hook aborts the
operation, so the harness is deny-by-default. A scanned script may read the
Python install and its own file (imports need that); every other file open,
every network action, and every subprocess/exec is recorded **and refused**
with `PermissionError`.

This is the core of a "run it somewhere safe and tell me if it's sketchy"
workflow. The sample script behaves like a credential stealer (reads an SSH
key, phones home); the harness blocks both attempts and reports exactly that.

Run the harness, never the target directly — the harness installs the audit
hook first, then executes the untrusted code.

## What the gate does not cover — read this before reusing the pattern

An in-process audit hook only sees Python-level API calls. It is a tripwire
and an evidence recorder **inside** the sandbox; the microVM is the actual
security boundary. In particular:

- **Native calls are invisible.** Code that drops to `ctypes` and calls libc
  directly raises no audit events, so it is neither gated nor traced. This
  payload reads a file the Python-level stealer above is denied — try it as
  `/tmp/target.py` against the harness and compare traces:

  ```python
  import ctypes
  libc = ctypes.CDLL(None)
  fd = libc.open(b"/tmp/canary.txt", 0)   # no "open" audit event fires
  buf = ctypes.create_string_buffer(64)
  libc.read(fd, buf, 64)
  print(buf.value)
  ```

  (Verified against this harness: the ctypes read succeeds with an empty
  event trace, while the same read through `open()` is blocked and traced.)
- **The trace is evidence, not proof of innocence.** An empty trace means
  "no gated Python-level actions were attempted", never "this code is safe".
  Anything the gate matters for must also be unreachable: run the scan with
  no real credentials, keys, or network routes inside the VM.
- **Output can lie.** The target's own stdout is reported as data; a script
  can print a fake verdict about itself. Trust the event trace, not the text.

## Run

```bash
cd examples/sandbox-scan-untrusted-code-ts
npm install
export SOLARI_API_KEY=slr_live_...   # https://console.getsolari.com
npm start
```

Built into a full tool — npm/PyPI package scanning, AI-written verdicts, and a
web UI: [github.com/Vinay152003/saferun](https://github.com/Vinay152003/saferun)
· [live demo](https://saferun-ten.vercel.app)

Source: [`index.ts`](index.ts)
