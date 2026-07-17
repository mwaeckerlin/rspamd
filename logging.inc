# Log level for the container stdout log (merged into the package's
# logging {} scope via local.d/logging.inc). `notice` keeps production
# quiet; `info` additionally shows every learn/scan decision — useful
# while debugging Bayes training or milter behaviour.
level = "${RSPAMD_LOG_LEVEL}";
