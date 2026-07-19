# Changelog

- 2026-07-18 **1.0.1**
    - Every configuration value from the environment is now validated
      before use; a malformed value (an embedded quote or newline that
      could smuggle extra configuration directives, an out-of-range
      port, a path-traversing domain or selector, a CRLF in the
      notification address) refuses to start with a clear
      `invalid <VAR>` error. Covered by the new config-validation test
      suite (`npm test`).
    - The standalone smoke compose now binds the milter and controller
      ports to loopback only — the controller trusts private source
      addresses without a password, and Docker's port forwarding makes
      every external client appear with such an address.
    - The missing image-contract test script shipped with the package
      scripts is now included, so `npm test` really runs.
    - Documentation: corrected the stale size-limit figures (ClamAV
      scan bounds, postfix message size default).

- 2026-07-17 **1.0.0**
    - Initial release: headless, shell-free Rspamd container
        - runtime contains only the Rspamd daemon, its libraries and configuration — no shell, no busybox, no perl, no package manager
        - one container covers DKIM signing, DKIM/DMARC/SPF verification, greylisting, Bayes spam scoring and antivirus hand-off together
    - Single `DKIM_DMARC` mode knob with four levels (`off`, `log`, `permissive`, `reject`)
        - same semantics as the retired opendkim/opendmarc pair in mailservice v2.x
        - `log` stamps verdicts into Authentication-Results without ever rejecting; `permissive` bounces broken or unknown-key signatures and DMARC `p=reject` failures; `reject` additionally bounces unsigned external mail
    - DKIM keys generated automatically on first start (one 2048-bit key per domain)
        - DNS TXT records printed to the container log
        - optional operator notification by e-mail (`NOTIFY_EMAIL`), delivered with a minimal built-in SMTP client
    - Score-based greylisting backed by Redis
        - clean first-time senders are never delayed; authenticated users are always exempt
    - Bayes classifier in Redis, global by default (per-user one switch away), trained event-driven from the mail client via IMAPSieve
    - ClamAV integration scanning the whole raw message; a virus hit rejects the mail at SMTP time with a clear error text
    - Marking is signature-safe: headers are added, the subject and body are never rewritten
    - Configurable thresholds and log level through environment variables; web UI for browsing recent decisions on the controller port
