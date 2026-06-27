"""
Language-specific race-condition patches
=======================================

Produces real, syntactically-correct synchronization patches for each
supported language's TOCTOU race. The goal is a fix that a developer can apply
directly and that genuinely closes the check-then-act window -- not a vague
recommendation.

Each function returns (patched_source, explanation) or (None, explanation) if
only guidance is possible for that language/shape.
"""

import re


def patch_java(src):
    """Add `synchronized` to the method so check-and-update is atomic per
    instance. If the method is static, synchronize on the class."""
    if "synchronized" in src:
        return None, "Method already uses synchronization."
    # static -> synchronized goes after static; instance -> after visibility
    if re.search(r"\bstatic\b", src):
        patched = re.sub(r"\b(static)\b", r"\1 synchronized", src, count=1)
    else:
        m = re.search(r"\b(public|private|protected)\b", src)
        if m:
            patched = src[:m.end()] + " synchronized" + src[m.end():]
        else:
            # no visibility modifier: add synchronized before return type
            patched = re.sub(r"^(\s*)(\w)", r"\1synchronized \2", src, count=1)
    return patched, ("Added `synchronized` so the check-and-update executes atomically per "
                     "instance; concurrent threads can no longer interleave between the guard "
                     "and the state mutation.")


def patch_go(src):
    """Insert a sync.Mutex lock/unlock at the top of the method body, using the
    receiver name. Assumes the struct has (or should have) a `mu sync.Mutex`."""
    # receiver name: func (r *Type) Name(...)
    recv = re.search(r"func\s*\(\s*(\w+)\s*\*?\s*\w+\s*\)", src)
    recv_name = recv.group(1) if recv else "s"
    brace = src.find("{")
    if brace < 0:
        return None, "Could not locate method body."
    if f"{recv_name}.mu.Lock()" in src:
        return None, "Method already locks the mutex."
    inject = f"\n\t{recv_name}.mu.Lock()\n\tdefer {recv_name}.mu.Unlock()"
    patched = src[:brace + 1] + inject + src[brace + 1:]
    return patched, (f"Acquired `{recv_name}.mu` (a sync.Mutex) at the start of the method with "
                     f"`defer`-ed unlock, making the check-and-update atomic. Add `mu sync.Mutex` "
                     f"to the struct if it is not already present.")


def patch_csharp(src):
    """Wrap the body in a `lock (_sync) { ... }` block using a private lock
    object `_sync`."""
    if re.search(r"\block\s*\(", src):
        return None, "Method already uses a lock block."
    brace = src.find("{")
    end = src.rfind("}")
    if brace < 0 or end < 0 or end <= brace:
        return None, "Could not locate method body."
    body = src[brace + 1:end]
    # indent the body one level and wrap
    indented = "\n".join(("    " + line if line.strip() else line) for line in body.split("\n"))
    patched = src[:brace + 1] + "\n        lock (_sync)\n        {" + indented + "}\n" + src[end:]
    return patched, ("Wrapped the critical section in `lock (_sync)` so only one thread executes "
                     "the check-and-update at a time. Declare `private readonly object _sync = new "
                     "object();` on the class.")


def patch_ruby(src):
    """Wrap the body in `@mutex.synchronize do ... end`."""
    if "synchronize" in src:
        return None, "Method already synchronizes."
    # def name(args)\n  <body>\n end
    m = re.match(r"(\s*def\s+[^\n]+\n)([\s\S]*?)(\n\s*end\s*)$", src)
    if not m:
        return None, "Could not parse Ruby method shape."
    head, body, tail = m.group(1), m.group(2), m.group(3)
    indented = "\n".join(("  " + line if line.strip() else line) for line in body.split("\n"))
    patched = f"{head}    @mutex.synchronize do\n{indented}\n    end{tail}"
    return patched, ("Wrapped the body in `@mutex.synchronize do ... end` so concurrent calls "
                     "cannot interleave. Initialize `@mutex = Mutex.new` in the constructor.")


def patch_js(src):
    """JS/TS: there is no built-in mutex, but we can serialize via a simple
    promise-chain mutex pattern. We provide a correct, minimal async-mutex
    wrapper and apply it to the method body when the method is async."""
    if "_mutex" in src or "runExclusive" in src:
        return None, "Method already serializes via a mutex."
    is_async = re.search(r"\basync\b", src)
    if not is_async:
        return None, ("In JavaScript, guard the operation with a transaction (SERIALIZABLE "
                      "isolation) or an async-mutex so concurrent requests cannot interleave. "
                      "Make the handler async and await an exclusive lock around the "
                      "check-and-update.")
    brace = src.find("{")
    end = src.rfind("}")
    if brace < 0 or end < 0:
        return None, "Could not locate method body."
    body = src[brace + 1:end]
    indented = "\n".join(("    " + line if line.strip() else line) for line in body.split("\n"))
    patched = (src[:brace + 1]
               + "\n    return await this._mutex.runExclusive(async () => {"
               + indented + "});\n" + src[end:])
    return patched, ("Serialized the check-and-update with an async mutex (`this._mutex."
                     "runExclusive(...)`) so concurrent requests run it one at a time. Initialize "
                     "`this._mutex = new Mutex()` (e.g. from the `async-mutex` package) in the "
                     "constructor, or use a DB transaction with SERIALIZABLE isolation.")


def patch_php(src):
    """PHP: wrap the check-and-update in a DB transaction with row locking. We
    can transform a clear `$this->db`/`$pdo` pattern; otherwise guidance."""
    note = ("Wrap the check-and-update in a database transaction with row locking so concurrent "
            "requests serialize: `$pdo->beginTransaction();` then `SELECT ... FOR UPDATE`, apply "
            "the change, `$pdo->commit();` (rollback on failure).")
    # if there's an obvious pdo/db handle, wrap the body in a transaction
    handle = None
    for h in ("$this->db", "$this->pdo", "$pdo", "$db", "$this->connection"):
        if h in src:
            handle = h
            break
    brace = src.find("{")
    end = src.rfind("}")
    if brace < 0 or end < 0:
        return None, note
    body = src[brace + 1:end]
    indented = "\n".join(("    " + line if line.strip() else line) for line in body.split("\n"))

    if handle:
        patched = (src[:brace + 1]
                   + f"\n        {handle}->beginTransaction();\n        try {{"
                   + indented
                   + f"\n            {handle}->commit();\n        }} catch (\\Throwable $e) {{"
                   + f"\n            {handle}->rollBack();\n            throw $e;\n        }}\n"
                   + src[end:])
        return patched, ("Wrapped the check-and-update in a database transaction with commit/rollback "
                         f"on `{handle}`. For full safety also use `SELECT ... FOR UPDATE` so the row is "
                         "locked for the duration of the transaction.")

    # no DB handle -> serialize with an advisory file lock (flock) so concurrent
    # PHP processes cannot interleave the check-and-update.
    if "flock(" in src:
        return None, "Method already uses a file lock."
    lock_setup = ('\n        $__lock = fopen(sys_get_temp_dir() . "/lb_" . md5(__METHOD__) . ".lock", "c");'
                  '\n        flock($__lock, LOCK_EX);\n        try {')
    lock_teardown = '\n        } finally {\n            flock($__lock, LOCK_UN);\n            fclose($__lock);\n        }\n'
    patched = src[:brace + 1] + lock_setup + indented + lock_teardown + src[end:]
    return patched, ("Serialized the check-and-update with an exclusive advisory file lock "
                     "(flock LOCK_EX) so concurrent PHP processes cannot interleave between the "
                     "check and the update. For multi-server deployments use a shared lock "
                     "(database row lock or Redis) instead.")


PATCHERS = {
    "java": patch_java,
    "go": patch_go,
    "c_sharp": patch_csharp,
    "ruby": patch_ruby,
    "javascript": patch_js,
    "typescript": patch_js,
    "tsx": patch_js,
    "php": patch_php,
}


def patch_for_language(language, src):
    fn = PATCHERS.get(language)
    if not fn:
        return None, None
    return fn(src)
