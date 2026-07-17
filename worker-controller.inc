# Override the built-in `controller` worker: bind on all interfaces
# so operators can `docker compose exec rspamd rspamc stat` from
# anywhere on the antispam network.
bind_socket = "*:11334";

# Privileged controller access (learn_spam/learn_ham, /stat, history)
# for private networks — dovecot's IMAPSieve Bayes autotrainer calls
# `rspamc learn_*` from the antispam container network. The port is
# never published to the outside; publishing it would be an operator
# error regardless of this setting.
secure_ip = ["127.0.0.0/8", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
