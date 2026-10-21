# Override the built-in `controller` worker: bind on all interfaces
# so operators can `docker compose exec rspamd rspamc stat` from
# anywhere on the antispam network.
bind_socket = "*:11334";

# Privileged controller access (learn_spam/learn_ham, /stat, history)
# without a password for RSPAMD_CONTROLLER_SECURE_IP — dovecot's
# IMAPSieve Bayes autotrainer calls `rspamc learn_*` from the antispam
# container network. The port is never published to the outside;
# publishing it would be an operator error regardless of this setting.
secure_ip = [${RSPAMD_CONTROLLER_SECURE_IP}];
${RSPAMD_CONTROLLER_PASSWORD_LINE}
