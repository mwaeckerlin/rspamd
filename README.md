# Rspamd

Headless, shell-free Rspamd container. Signs outgoing mail with DKIM,
verifies incoming DKIM / DMARC / SPF, greylists, runs a Bayes
classifier trained by IMAPSieve, hands mail parts to ClamAV, and — via
a single `DKIM_DMARC` mode switch — either logs its verdict, softly
enforces standards, or hard-rejects on failure.

Intended primary use inside `mwaeckerlin/mailservice` (Docker Compose
mail stack: postfix, dovecot, postfixadmin, snappymail). Works
standalone against any postfix that speaks the milter protocol on
port 11332.

## Environment variables

| Variable                | Default          | Description                                                                                                                                                                                                                                     |
|-------------------------|------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `DOMAINS`               | —                | Space-separated list of domains to sign for. One 2048-bit RSA key is generated per domain on first start.                                                                                                                                       |
| `DOMAIN`                | —                | Single-domain fallback if `DOMAINS` is unset. One of the two is required.                                                                                                                                                                       |
| `SELECTOR`              | `mail`           | DKIM selector (DNS label). Same selector name is used for every domain.                                                                                                                                                                          |
| `DKIM_DMARC`            | `reject`         | Enforcement mode. One of `off` (no verify, no A-R stamping), `log` (verify + stamp Authentication-Results, never reject), `permissive` (reject bad-sig / unknown-key / DMARC-`p=reject`-fail; accept unsigned), `reject` (also reject unsigned). |
| `RSPAMD_REJECT_SCORE`   | `15`             | Spam-score threshold above which the mail is rejected with `550 message rejected by policy`. Rspamd's own default; conservative on purpose (Marc's philosophy: lieber zu hoch als legitime Mail bouncen).                                       |
| `RSPAMD_ADDHEADER_SCORE`| `6`              | Score above which the mail is stamped with `X-Spam-Flag: YES`, `X-Spam-Status`, `X-Spam-Level`. Informational only (`RSPAMD_REJECT_SCORE` already rejected higher scores at SMTP time). Header-add is signature-safe; the subject is **never** rewritten, because that would invalidate the sender's DKIM signature. |
| `RSPAMD_GREYLIST_SCORE` | `5`              | Score above which greylisting kicks in (soft 4xx defer). **Score-based** — clean mail from unknown senders is never delayed (unlike postgrey, which delayed every unknown triplet). Own users / SASL-authenticated clients are always exempt.  |
| `RSPAMD_GREYLIST_TIMEOUT` | `300s`         | Greylist retry delay (classic postgrey value). The e2e suite shortens this to `5s`.                                                                                                                                                             |
| `RSPAMD_GREYLIST_EXPIRE` | `35d`           | How long a passed triplet stays known in Redis (classic postgrey autowhite).                                                                                                                                                                    |
| `RSPAMD_CHECK_LOCAL`    | `false`          | `true` also greylists mail from `local_addrs` clients. Leave off in production.                                                                                                                                                                 |
| `RSPAMD_LOCAL_ADDRS`    | RFC1918 + loopback | Client networks treated as «own»: their mail skips SPF/DKIM/DMARC verification and greylisting and takes the outbound (signing) path. The e2e stack narrows this to `127.0.0.0/8` so the test-runner counts as external.                       |
| `RSPAMD_SIGN_NETWORKS`  | `127.0.0.0/8`    | Client networks whose mail is DKIM-signed even without SASL authentication (on top of `sign_local` and `sign_authenticated`).                                                                                                                   |
| `RSPAMD_BAYES_PER_USER` | `false`          | `false` = one global Bayes classifier (right for small deployments; hits Rspamd's 200-messages-per-class threshold in days). `true` = per-user Bayes (right for large multi-tenant, takes months per user to reach threshold).                    |
| `RSPAMD_LOG_LEVEL`      | `notice`         | Container-stdout log level. `info` additionally shows every learn/scan decision — useful when debugging Bayes training or milter behaviour.                                                                                                      |
| `REDIS_HOST`            | `redis`          | Hostname of the Redis backend for Bayes / greylist / ratelimit state.                                                                                                                                                                            |
| `REDIS_PORT`            | `6379`           |                                                                                                                                                                                                                                                  |
| `CLAMAV_HOST`           | `clamav`         | Hostname of the ClamAV daemon (`clamd`).                                                                                                                                                                                                        |
| `CLAMAV_PORT`           | `3310`           |                                                                                                                                                                                                                                                  |
| `NOTIFY_EMAIL`          | *(empty)*        | Optional. If set, the operator receives one plain-text mail whenever new DKIM keys are auto-generated on start-up (listing the DNS TXT records to publish). Empty = only stdout log.                                                            |
| `NOTIFY_SMTP`           | `127.0.0.1:25`   | SMTP host:port used to deliver the `NOTIFY_EMAIL` message. Must be a numeric IPv4 — no DNS lookup in the init helper.                                                                                                                            |
| `HOSTNAME`              | `mail.local`     | Used as `From:` domain in the DKIM-key notification mail.                                                                                                                                                                                        |

## DKIM key generation and DNS-record notification

On first start, `init` calls `rspamadm dkim_keygen -s <selector>
-b 2048 -d <domain>` for every domain in `DOMAINS` that does not
already have a `${selector}-${domain}.key` file under
`/var/lib/rspamd/dkim/`, and prints the resulting BIND-formatted DNS
TXT record with a banner to stdout — visible via
`docker compose logs rspamd`.

If `NOTIFY_EMAIL` is set, the same records are additionally delivered
by e-mail to that address using minimal in-process SMTP (no shell, no
extra binary, no external client). Delivery is best-effort and never
blocks start-up: a failing SMTP round-trip only logs a warning; the
records still appear on stdout.

## `DKIM_DMARC` — the single mode knob

|                                                 | `off`             | `log`                           | `permissive` (recommended default for a real MX) | `reject` (image default)      |
|-------------------------------------------------|-------------------|---------------------------------|--------------------------------------------------|-------------------------------|
| Correct DKIM signature                          | accept, no A-R    | accept, `dkim=allow`            | accept, `dkim=allow`                              | accept, `dkim=allow`          |
| No DKIM signature                               | accept, no A-R    | accept, `R_DKIM_NA`             | accept                                            | reject if the score exceeds `RSPAMD_REJECT_SCORE` |
| Bad DKIM signature / unknown key                | accept, no A-R    | accept, `R_DKIM_INVALID`        | **reject** (5xx)                                  | **reject** (5xx)              |
| DMARC `_dmarc … p=reject`, alignment fails      | accept, no A-R    | accept, `DMARC_POLICY_REJECT`   | **reject** (5xx)                                  | **reject** (5xx)              |
| DMARC `p=none` or `p=quarantine`, alignment fails | accept, no A-R  | accept, verdict stamped         | accept                                            | accept                        |
| Spam score ≥ `RSPAMD_REJECT_SCORE`              | delivered         | delivered + `X-Spam-Result`     | delivered + `X-Spam-Result`                       | **reject** (5xx)              |
| Virus detected by ClamAV                        | delivered         | delivered + `CLAM_VIRUS` symbol | **reject** (5xx)                                  | **reject** (5xx)              |

`log` mode is meant to be run for a few days after enabling this
container in production. Grep delivered mail's
`Authentication-Results:` and `X-Spamd-Result:` headers for the
verdicts you would have rejected; when nothing legitimate is caught,
escalate to `permissive` (or `reject`, if every legitimate sender you
receive from is known to sign).

## Volumes to persist

- `/var/lib/rspamd/dkim/` — private DKIM keys per domain.
  **Critical**: losing this volume invalidates every published DNS
  TXT record; outgoing mail is still signed but with a new key, so
  receivers stop verifying until the DNS is rolled forward.
- `/var/lib/rspamd/` — compiled Lua cache and misc state. Non-
  critical; regenerated on start.

Bayes / greylist / ratelimit state lives in **Redis** — see the
sibling `mwaeckerlin/redis` container and its `/data` volume.

## Postfix integration

In `postfix/main.cf` (via the `RSPAMD` env on `mwaeckerlin/postfix`):

    smtpd_milters = inet:rspamd:11332
    non_smtpd_milters = inet:rspamd:11332
    milter_default_action = accept
    milter_protocol = 6

The postfix Dockerfile in `mwaeckerlin/postfix` adds this
automatically when `RSPAMD` env is set (host or host:port; default
port 11332).

## Image layout

Three-stage build, following the `mwaeckerlin/nginx`, `mwaeckerlin/
php-fpm`, `mwaeckerlin/opendkim` and `mwaeckerlin/opendmarc`
pattern:

1. **`init`** — compiles `init.cpp` statically with `g++ -static -Os
   -flto`. The resulting binary parses env, generates DKIM keys via
   `rspamadm dkim_keygen`, optionally notifies via minimal in-process
   SMTP, stages `/etc/rspamd/local.d/*.conf` from templates, and
   `execv`s the daemon.
2. **`build`** — installs `rspamd` on the Alpine base, then uses
   `tar cph … + ldd` to collect only the binaries, shared libraries,
   Lua modules and configs the runtime needs into `/root/`.
3. **runtime** — `FROM mwaeckerlin/scratch`, `COPY --from=build
   /root/ /`. No shell, no package manager, no perl, no busybox.
   `ENTRYPOINT ["/usr/bin/init"]`.

Debugging on this shell-free image:

    docker compose logs rspamd            # every rspamd decision streams here
    docker compose exec rspamd rspamc stat
    docker compose exec rspamd rspamc symbols < mail.eml

The rspamd web UI is available on port 11334 (`http://<host>:11334/`)
if you expose it — useful for browsing the history of recent
decisions per message.
