# LogicBreaker AI — False-Positive Reduction (WordPress hardening)

Motivation: a scan of WordPress 6.4.2 produced 643 findings — a false-positive
flood that violated the "Zero False Positives" principle. This release drives
real-world FPs to (near) zero while keeping the detection benchmark perfect.

## Validated results
- Detection benchmark expanded 74 -> **103 cases** (48 vulnerable + 55 safe),
  now passing at **100% precision / 100% recall / 0% FP**. The safe set adds
  realistic FP look-alikes: browser JS with exec/SQL-looking code, $wpdb->prepare
  queries, libxml-disabled XML, integer-ID IN() lists, placeholder-secret JS,
  in_array-whitelisted params, is_admin()+$_GET, gmdate/sanitize_key SQL vars,
  wp_safe_redirect, and prepare-wrapped interprocedural flows.
- WordPress slices: 49-file slice 9 -> 0 findings; 98-file slice 8 -> 3, and the
  3 remaining are TRUE positives (real chmod(...,0777) and md5 legacy password
  compat), not false alarms.

## Key fixes
1. Language mislabel: taint findings now carry the real language (no more .js/.php
   reported as "python").
2. Browser/client-side JS awareness: server-side vuln classes (SQLi, command-inj,
   path, SSRF, XXE, deser, TOCTOU, etc.) are dropped on confirmed client JS.
   Node/UMD bundles (module.exports/__dirname) are NOT treated as server signals.
3. JS command-injection sinks tightened to real child_process forms (no bare
   exec()/eval() matching RegExp.exec/eval).
4. PHP SQLi precision: recognises $wpdb->prepare, array_map('intval'), absint,
   in_array allow-lists, esc_sql/escape_by_ref/sanitize_*/gmdate provenance
   (transitively), and frameworks' {$wpdb->table} identifiers. The matcher now
   requires real untrusted input (or a parameter) flowing into the SQL.
5. Interprocedural SQLi: the multi-hop summary no longer inherits a sink across a
   call boundary that sanitises the argument (e.g. $wpdb->get_row($wpdb->prepare
   (... %s ..., $option))), including values sanitised on an earlier line.
6. XXE: call-form parsers only (no bare libxml/xmlreader substrings), recognises
   PHP libxml_disable_entity_loader / PHP-8 default-safe / loadHTML, and requires
   externally-influenced XML. File-level mitigation honoured.
7. TOCTOU: only the two genuine patterns fire — numeric balance/quota decrement
   after a latency window, and file check-then-act on an externally-influenced
   path. Per-member resource identity (no more "all $this-> members are one").
8. Broken-Auth (CWE-602): is_admin() predicate no longer mistaken for a client
   role; capability/nonce checks and array-lookup-only role uses suppressed.
9. IDOR / Rate-limit / Sensitive-info / Open-redirect / XSS: secret/key
   verification recognised as authz; auth filter callbacks excluded; secret
   keywords inside strings ignored; wp_safe_redirect/esc_url recognised; XSS now
   requires the value in HTML to actually be request-derived.
10. New CLI flag: `--min-confidence` / `--confidence-threshold` hides findings
    below a confidence cutoff across reporting, dynamic testing, and patching.

Architecture unchanged (AST + taint, no regex-for-decisions); every change was
gated on the benchmark staying green.
