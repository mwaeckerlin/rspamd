# Global rspamd options overrides (merged into the options {} scope).
#
# local_addrs decides which SMTP client IPs count as "our own
# network": mail from those addresses skips the external checks
# (SPF/DKIM verify, DMARC, greylist) and takes the outbound path
# (DKIM signing). Production default is RFC1918 + loopback — every
# real external sender arrives with a public IP, every own service
# lives on a container network. The e2e stack narrows this to
# loopback so the test-runner (necessarily on a 10.x docker network)
# is treated as an external sender and the verify paths actually run.
local_addrs = "${RSPAMD_LOCAL_ADDRS}";
