# I have a bug I believe might be security related

**Please file the bug either way.** Everything goes to the same place - the
Issue Tracking System at <https://bugs.openldap.org/>. The only question this
document answers is whether to tick the **PRIVATE SECURITY BUG** box when you
do.

Ticking the box keeps the report out of public view until a fix is ready. That
is valuable when it is warranted, and it costs everyone time when it is not:
the report is invisible to other users who might be hitting the same bug,
nobody else can help diagnose it, and it does not get fixed any faster.

If after reading this you genuinely cannot tell: **tick the box.** A private
report that turns out to be an ordinary bug can easily be made public. Not so
much the other way around.

## The rule

> A crash, an abort, an assertion failure, or a hang is a **bug**, not a
> security issue.

OpenLDAP treats an issue as security-relevant only when it gives an attacker
**capability or information they would not otherwise have**. In practice that
means one of:

- **Memory corruption with a controllable consequence** - heap/stack overflow,
  out-of-bounds write, use-after-free, double-free, type confusion. Not a NULL
  dereference, and not an out-of-bounds *read* that only crashes.
- **Authentication or authorization bypass** - acting as an identity you are
  not entitled to, reading or writing data that should have been denied by the
  standing ACLs, or reaching a database (especially `cn=config`) you have no
  rights in.
- **Credential or key disclosure** - bind passwords, password hashes, TLS
  private keys, SASL/Kerberos secrets, replication credentials, ...
- **Loss of channel protection** - anything letting a network attacker read,
  modify, or impersonate a session the software believes is authenticated or
  encrypted.
- **Cross-session data leakage** - one client receiving another client's
  results.

Denial of service is mostly not in scope, but the exceptions differ per
component; see below.

If the issue only happens in unusual configurations, this doesn't by itself
discount the issue, only its *severity*. So long as the attacker can abuse
this in a supported configuration, we want to know.

## Which side of the trust boundary are you on?

By far, most security reports where we choose to reclassify happen because
they do not align with who/what OpenLDAP deems trusted in each scenario.

### `libraries/liblber` - ASN.1 BER (de)serialisation and I/O

The inputs and data are **not trusted**. So long as the user abides by the
documentation (and that includes setting reasonable limits in
`LBER_SB_OPT_SET_MAX_INCOMING`), liblber is designed to process arbitrary
data.

Highest-value surfaces: `ber_get_next` framing, `ber_scanf`/`ber_get_*`
decoding.

### `libraries/libldap` - client libraries and internal abstractions

**The untrusted party is the server**, a man-in-the-middle or data that is
promised to be opaque to the library. There is no remote client as these
libraries *are* the client: they decode the LDAP responses that a
possibly-hostile server sent them.

What raises the stakes: **slapd is itself an LDAP client** in its syncrepl,
`back-ldap`, `back-meta`, and referral chasing roles. A decoder bug in "the
client libraries" can be driven by a hostile replication peer or proxied-to
server straight into the **slapd server process**. Do not talk yourself out of
a libldap report on the grounds that it "only affects command-line tools".

Highest-value surfaces: response parsers (`result.c`, `controls.c`,
`references.c`, `extended.c`, ...), TLS peer verification, referral chasing,
and DN / X.509-name / schema string parsing.

### `servers/slapd` - the directory server

**The untrusted party is the remote client**, anonymous or authenticated, plus
whatever is already stored in the backends. A replication provider or
proxied-to upstream is **also an untrusted source** for many purposes.

In addition to the obvious, the project cares about the **database boundary**.
slapd serves several databases at once, including the privileged `cn=config`,
where write access is effectively code execution (e.g. `olcModuleLoad`).
Crossing between databases can be *legitimate and intentional* - proxying,
glue/subordinate databases, syncrepl and proxy-authorization all do it. The
security property is that the primitives which can cross it
(`select_backend()` as the obvious one; there are others) **cannot be
coerced** into operating on a database the actor is not entitled to.

So: if you can steer an operation, or a replicated change, into a database you
have no rights in - particularly `cn=config` - it is a clear security
violation and we want you to tick the box, even if nothing crashes and even if
it looks like it needs an unusual configuration.

Data integrity violations are often in scope except when they are an
inevitable consequence of the chosen replication topology. Loss of
data confidentiality is usually in scope.

Highest value surfaces: operation and control parsers and schema validation
(`schema*.c`) are reachable by anyone. ACL engine is complex and also inspects
untrusted data.

### `servers/lloadd` - the load balancer

**Both sides are untrusted at once.** lloadd faces untrusted clients at the
front and acts as an LDAP *client* to a pool of network-reachable upstream
slapds at the back. Malicious payload can arrive from either direction.

Two things to check before reporting:

- lloadd is normally built and deployed as a **slapd module**. It lives
  inside the slapd address space and often shares its TLS configuration - so a
  memory-safety defect in lloadd is a **slapd-process compromise**, not a
  balancer-only one. That might raise severity but does not change what
  counts.
- lloadd is a **router, not a content firewall**. By design it works at the
  session/framing layer: it frames the PDU (msgid, operation tag, controls
  envelope) and forwards the request body and control blob largely unexamined.
  "Malicious content passes through lloadd to the upstream" is expected
  behaviour - content validation is the upstream slapd's job. What lloadd
  *does* parse (framing, message routing, the controls envelope, the bind/auth
  state machine) is in scope, as is anything that misroutes a PDU to the wrong
  session.

### `libraries/liblmdb` - LMDB

**LMDB trusts its own database files by contract.** `data.mdb` and `lock.mdb`
are assumed not to be mutated by an untrusted entity; the embedder owns that
responsibility. On open, only the magic number and format version are checked,
no content or offsets are bounds-checked.

So a crash, out-of-bounds read, or corruption caused by a **crafted, tampered,
or substituted database file is out of scope** - it is not an LMDB bug. Same
for a hostile local writer poisoning `lock.mdb`, and for `mdb_load` fed
untrusted text.

What *is* in scope is LMDB's own correctness and memory safety when driven
**through its API on its own files**: adversarial-but-valid operation sequences
(DUPSORT, overflow pages, near-maximum key/value sizes), MVCC concurrency
races, and internal defects reachable under `MDB_WRITEMAP`.

## Denial of service

The line differs by component, so check the one you are reporting against.

- **slapd**:
  - server crash even by an unauth'd client is probably not a security issue.
    It is still a **grave bug** and we will be grateful if you tick the box
  - exhaustion by *flooding* (connections, threads, pending operations) is out
    of scope: it is predictable for any network service and administrators
    plan for it. A **single operation** that amplifies into disproportionate,
    non-obvious CPU or memory cost is a high-severity bug whose security
    status is judged case by case. Worth ticking the box.
- **libldap/liblber** - exhaustion counts only when the **library forces it**
  and the application linking the library cannot avoid it through an existing,
  more efficient API. `ber_get_next` enforces `sb_max_incoming`, so a consumer
  can already bound raw message size, similar with recursion depth. What
  matters is amplification surviving that cap.
- **lloadd** - resource exhaustion against the balancer is not currently
  treated as a security issue: LDAP session semantics constrain which
  mitigations are actually achievable. File it as an ordinary bug.
- **LMDB** - unbounded database growth from stale long-lived readers affects
  availability and is not in scope; the embedder is expected to call
  `mdb_reader_check`, but library-side contributions to it are worth reporting.

## Things we don't treat as security issues

These are still real bugs and we still want the reports - just file them
publicly. Expect them to be handled as ordinary bugs or documentation fixes:

- **Crashes, aborts, assertion failures and hangs**, per the rule above. This
  is the single most common reason a report gets reclassified.
- **PROXY protocol source-IP spoofing.** `pldap://` / `pldaps://` listeners
  trust the claimed client address unconditionally, by design and as documented
  in `slapd.8`. Administrators must firewall those ports to trusted balancers.
- **A client sending credentials in cleartext before StartTLS completes.** That
  is client-side behaviour; the project's guidance is to prefer `ldaps://`. A
  *server-side* mismatch between TLS state and the session state slapd acts on
  is a different matter and does count.
- **A crash on a corrupted or crafted LMDB file** - see above.
- **Anything requiring an administrator to have already enabled an explicitly
  documented-as-unsafe option** (`MDB_NOLOCK`, permissive `cn=config` ACLs,
  disabled certificate verification).
- **Missing or incomplete audit logging.** slapd offers `accesslog`/`auditlog`
  but is not by itself a guaranteed audit authority; lloadd is a forwarder, not
  a system of record. Inaccurate audit logging could be a security issue if it
  mischaracterises e.g. the acting identity.
- **Supply-chain / build-time concerns** (autoconf, vendored dependencies).
  Real, but not specific to any runtime surface here.
- Features clearly marked as incomplete/unsupported and disabled by default
  (e.g. component matching). Implementers are however interested in potential
  security implication of their work so labeling the issue as such even
  without ticking the box

A note on incentives, since it comes up: a public ITS entry is not a lesser
outcome. It is attributed to you and permanently visible, which a private
report is not - and if you follow the
[contribution and AI policy](https://www.openldap.org/devel/contributing.html)
and send a patch, you get a commit in the repository with your name on it.
What the box does *not* do is convert a crash into a CVE. Ticking it on a bug
that does not meet the bar above delays the fix and gets reclassified at the
end anyway. It does not change the outcome in your favour.

## What to include

- Affected component and version / git commit.
- Which trust boundary is being crossed, in the terms above - who the attacker
  is (unauthenticated client? authenticated client? hostile server? replication
  provider? local user?) and what they gain that they did not have.
- A reproducer: configuration, the request or response bytes, and the
  observable result.
- For memory corruption, an ASan or Valgrind trace rather than a plain
  backtrace. The data it provides is much richer by identifying the cause and
  given the above makes it much clearer to us where a bug ends and a security
  issue starts.
