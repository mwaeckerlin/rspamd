# Override the built-in `rspamd_proxy` worker: bind on all
# interfaces so the postfix container can reach the milter socket.
# Self-scan mode → rspamd both proxies AND processes; simpler than
# running a separate `normal` worker.
bind_socket = "*:11332";
milter = yes;
upstream "local" {
    default = yes;
    self_scan = yes;
}
count = 4;
max_retries = 5;
reject_message = "message rejected by policy";
