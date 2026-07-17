/**

Rspamd init: minimal, shell-free entrypoint for the rspamd container.

Follows the same three-stage / statically-linked / execvp() pattern as
the sibling mwaeckerlin/opendkim init: parse env, compose runtime
config, exec the daemon. The runtime image contains no shell, no perl,
no busybox.

Behaviour:

  1. For every domain in DOMAINS: if `${LOCAL_LIB}/dkim/<selector>-
     <domain>.key` does not exist, generate a fresh 2048-bit RSA key via
     `rspamadm dkim_keygen -s <selector> -b 2048 -d <domain>` and print
     the resulting BIND-style DNS TXT record to stdout (`docker compose
     logs rspamd` picks it up).
  2. If NOTIFY_EMAIL is set AND at least one new key was generated:
     open a TCP connection to NOTIFY_SMTP (default `postfix:25`) and
     speak plain SMTP directly — no external client, no shell, no
     msmtp binary. On any error, log a warning and continue;
     notification never blocks start-up.
  3. Rebuild `${LOCAL_LIB}/dkim/signing_table` and `key_table` (one
     line per domain) so rspamd's dkim_signing module picks up the
     current DOMAINS list.
  4. Compose `/etc/rspamd/local.d/*.conf` by copying the templates
     from `/etc/rspamd.d.template/` and substituting `${VAR}`
     placeholders from env. Directives that depend on DKIM_DMARC:
       - off        rspamd's dkim + dmarc + arc + spf + greylist
                    modules are all disabled — the milter passes
                    through untouched
       - log        modules enabled, all reject actions set to accept
                    (score-only stamping into Authentication-Results)
       - permissive DMARC reject on p=reject; DKIM invalid/tempfail
                    reject via score; greylist active
       - reject     same as permissive; on the DKIM side there is
                    nothing stricter to enable on rspamd — «reject
                    unsigned» is enforced by a very high symbol
                    score on R_DKIM_NA
  5. execvp("/usr/sbin/rspamd", "-f", …).

Supports --healthcheck: TCP-probes the proxy worker at 127.0.0.1:11332
and the controller at 127.0.0.1:11334. Both must be reachable.

*/

#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr const char *RSPAMD          = "/usr/bin/rspamd";
constexpr const char *RSPAMADM        = "/usr/bin/rspamadm";
constexpr const char *TEMPLATE_DIR    = "/etc/rspamd.d.template";
constexpr const char *LOCAL_D_DIR     = "/etc/rspamd/local.d";
constexpr const char *DKIM_DIR        = "/var/lib/rspamd/dkim";
constexpr const char *PID_FILE        = "/run/rspamd/rspamd.pid";

std::string
env_or(const char *name, const std::string &fallback = {}) {
  const char *v = std::getenv(name);
  return (v && *v) ? std::string(v) : fallback;
}

std::vector<std::string>
split_ws(const std::string &s) {
  std::vector<std::string> out;
  std::istringstream is(s);
  std::string tok;
  while (is >> tok) out.push_back(tok);
  return out;
}

std::string
read_file(const fs::path &p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) throw std::runtime_error("cannot read " + p.string());
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

void
write_file(const fs::path &p, const std::string &content) {
  std::ofstream out(p, std::ios::binary | std::ios::trunc);
  if (!out) throw std::runtime_error("cannot write " + p.string());
  out << content;
}

int
run_capture(const std::vector<const char *> &argv, std::string &out) {
  int pipefd[2];
  if (pipe(pipefd) < 0) throw std::runtime_error("pipe");
  pid_t pid = fork();
  if (pid < 0) throw std::runtime_error("fork");
  if (pid == 0) {
    close(pipefd[0]);
    dup2(pipefd[1], 1);
    dup2(pipefd[1], 2);
    close(pipefd[1]);
    std::vector<char *> a;
    for (auto *s : argv) a.push_back(const_cast<char *>(s));
    a.push_back(nullptr);
    execvp(a[0], a.data());
    _exit(127);
  }
  close(pipefd[1]);
  char buf[4096];
  ssize_t n;
  while ((n = read(pipefd[0], buf, sizeof buf)) > 0) out.append(buf, n);
  close(pipefd[0]);
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// Substitute ${VAR} references in `s` with the value of getenv(VAR),
// or the supplied fallback map. Unknown variables become empty.
std::string
substitute(const std::string &s,
           const std::map<std::string, std::string> &vars) {
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0; i < s.size(); ) {
    if (i + 1 < s.size() && s[i] == '$' && s[i + 1] == '{') {
      auto end = s.find('}', i + 2);
      if (end == std::string::npos) { out += s[i++]; continue; }
      std::string name = s.substr(i + 2, end - i - 2);
      auto it = vars.find(name);
      if (it != vars.end()) out += it->second;
      else                  out += env_or(name.c_str());
      i = end + 1;
    } else {
      out += s[i++];
    }
  }
  return out;
}

// --------------------------------------------------- DKIM keygen ----------

// Extract the base64 `p=` body from `rspamadm dkim_keygen`'s stdout,
// which prints the private key first, then the BIND-formatted TXT
// record on stderr — captured together in `combined`.
bool
extract_txt_record(const std::string &combined, std::string &out) {
  // rspamadm's format:
  //   <priv PEM>
  //   <selector>._domainkey IN TXT ( "v=DKIM1; k=rsa; " "p=..." )
  auto pos = combined.find("_domainkey");
  if (pos == std::string::npos) return false;
  auto start = combined.rfind('\n', pos);
  out = combined.substr(start == std::string::npos ? 0 : start + 1);
  return true;
}

// Returns true when a new key was generated for this domain.
bool
ensure_dkim_key(const std::string &domain, const std::string &selector,
                std::string &txt_record_out) {
  const fs::path priv = fs::path(DKIM_DIR) / (selector + "-" + domain + ".key");
  const fs::path txt  = fs::path(DKIM_DIR) / (selector + "-" + domain + ".txt");
  if (fs::exists(priv)) return false;

  fs::create_directories(DKIM_DIR);
  std::cerr << "**** Generating DKIM key: selector=" << selector
            << " domain=" << domain << std::endl;

  std::string combined;
  int rc = run_capture(
      {RSPAMADM, "dkim_keygen", "-s", selector.c_str(),
                 "-d", domain.c_str(),
                 "-b", "2048",
                 "-k", priv.c_str()},
      combined);
  if (rc != 0)
    throw std::runtime_error("rspamadm dkim_keygen failed for " + domain +
                             ": exit " + std::to_string(rc));

  std::string record;
  if (!extract_txt_record(combined, record))
    throw std::runtime_error("could not parse dkim_keygen output for " + domain);

  write_file(txt, record);
  txt_record_out = record;

  std::cout << "\n"
            << "==================================================================\n"
            << "  DKIM key generated \xe2\x80\x94 add this DNS TXT record to " << domain << ":\n"
            << "==================================================================\n"
            << record
            << "==================================================================\n\n";
  return true;
}

// --------------------------------------------------- SMTP notify ----------

// Minimal SMTP client: connect, greet, deliver a single text mail,
// quit. Best-effort — every failure is logged and swallowed so init
// never blocks startup on a notification hiccup.
bool
smtp_send(const std::string &host, int port,
          const std::string &from, const std::string &to,
          const std::string &subject, const std::string &body,
          std::string &err) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) { err = "socket()"; return false; }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
    // Not a numeric IPv4 — the container's resolver handles it via
    // getaddrinfo. For minimal init we stick to numeric; document
    // NOTIFY_SMTP=<ip>:<port> in the README.
    err = "NOTIFY_SMTP must be a numeric IPv4 address (got \"" + host + "\")";
    close(sock);
    return false;
  }
  if (connect(sock, reinterpret_cast<sockaddr *>(&addr), sizeof addr) < 0) {
    err = std::string("connect: ") + std::strerror(errno);
    close(sock);
    return false;
  }

  auto reply = [&](const std::string &cmd, int expect) -> bool {
    if (!cmd.empty()) send(sock, cmd.data(), cmd.size(), 0);
    char buf[1024];
    ssize_t n = recv(sock, buf, sizeof buf - 1, 0);
    if (n <= 0) { err = "recv timeout / EOF"; return false; }
    buf[n] = 0;
    int code = std::atoi(buf);
    if (code / 100 != expect / 100) {
      err = std::string("unexpected SMTP reply: ") + buf;
      return false;
    }
    return true;
  };

  auto payload =
      "From: " + from + "\r\n" +
      "To: " + to + "\r\n" +
      "Subject: " + subject + "\r\n" +
      "\r\n" + body + "\r\n.\r\n";

  bool ok =
      reply("",                                                220) &&
      reply("EHLO rspamd-init\r\n",                            250) &&
      reply("MAIL FROM:<" + from + ">\r\n",                    250) &&
      reply("RCPT TO:<" + to + ">\r\n",                        250) &&
      reply("DATA\r\n",                                        354) &&
      reply(payload,                                           250) &&
      reply("QUIT\r\n",                                        221);
  close(sock);
  return ok;
}

void
notify_new_keys(const std::vector<std::pair<std::string, std::string>> &new_keys) {
  const std::string notify_email = env_or("NOTIFY_EMAIL");
  if (notify_email.empty() || new_keys.empty()) return;

  const std::string notify_smtp = env_or("NOTIFY_SMTP", "127.0.0.1:25");
  auto colon = notify_smtp.find(':');
  std::string host = notify_smtp.substr(0, colon);
  int port = colon == std::string::npos ? 25 : std::atoi(notify_smtp.c_str() + colon + 1);

  std::string body =
      "One or more DKIM signing keys were auto-generated on start-up.\n"
      "Publish each of the following DNS TXT records to make DKIM signing\n"
      "for these domains verifiable by receivers:\n\n";
  for (const auto &kv : new_keys) {
    body += "----- " + kv.first + " -----\n" + kv.second + "\n";
  }
  body +=
      "\nUntil the DNS records are live, outgoing mail from these domains\n"
      "will still be signed but receivers will not be able to verify.\n";

  std::string from = "rspamd@" + env_or("HOSTNAME", "mail.local");
  std::string err;
  if (smtp_send(host, port, from, notify_email,
                "New DKIM keys generated — publish DNS records", body, err)) {
    std::cerr << "**** DKIM key notification mailed to " << notify_email
              << " via " << notify_smtp << std::endl;
  } else {
    std::cerr << "**** WARNING: DKIM key notification to " << notify_email
              << " via " << notify_smtp << " failed: " << err
              << " (DNS records still printed to stdout above)" << std::endl;
  }
}

// --------------------------------------------------- config staging -------

// Write signing_table and key_table maps under DKIM_DIR — one line per
// domain in DOMAINS. Format is rspamd's OpenDKIM-compatible map pair:
//   signing_table:  *@<domain> <keyname>
//   key_table:      <keyname> <domain>:<selector>:<private-key-path>
void
write_dkim_maps(const std::vector<std::string> &domains,
                const std::string &selector) {
  std::string signing;
  std::string keys;
  for (const auto &d : domains) {
    signing += "*@" + d + " " + d + "\n";
    keys    += d + " " + d + ":" + selector + ":"
             + std::string(DKIM_DIR) + "/" + selector + "-" + d + ".key\n";
  }
  write_file(fs::path(DKIM_DIR) / "signing_table", signing);
  write_file(fs::path(DKIM_DIR) / "key_table",     keys);
}

// Populate /etc/rspamd/local.d from the shipped templates, substituting
// env references. `mode_vars` overrides the mode-dependent knobs.
void
stage_configs(const std::map<std::string, std::string> &mode_vars) {
  fs::create_directories(LOCAL_D_DIR);
  for (const auto &entry : fs::directory_iterator(TEMPLATE_DIR)) {
    if (!entry.is_regular_file()) continue;
    auto name = entry.path().filename().string();
    auto content = substitute(read_file(entry.path()), mode_vars);
    write_file(fs::path(LOCAL_D_DIR) / name, content);
  }
}

// Translate DKIM_DMARC to per-module knob values. Multi-line values
// (…_ACTIONS / …_RULES / …_ACTION) are substituted verbatim into the
// templates, so a mode can inject a whole config block or nothing.
std::map<std::string, std::string>
mode_variables(const std::string &mode) {
  std::map<std::string, std::string> v;
  // Reasonable defaults independent of mode
  v["RSPAMD_GREYLIST_SCORE"]   = env_or("RSPAMD_GREYLIST_SCORE",   "5");
  v["RSPAMD_ADDHEADER_SCORE"]  = env_or("RSPAMD_ADDHEADER_SCORE",  "6");
  v["RSPAMD_REJECT_SCORE"]     = env_or("RSPAMD_REJECT_SCORE",    "15");
  v["RSPAMD_BAYES_PER_USER"]   = env_or("RSPAMD_BAYES_PER_USER",   "false");
  v["RSPAMD_GREYLIST_TIMEOUT"] = env_or("RSPAMD_GREYLIST_TIMEOUT", "300s");
  v["RSPAMD_GREYLIST_EXPIRE"]  = env_or("RSPAMD_GREYLIST_EXPIRE",  "35d");
  v["RSPAMD_CHECK_LOCAL"]      = env_or("RSPAMD_CHECK_LOCAL",      "false");
  v["RSPAMD_LOG_LEVEL"]        = env_or("RSPAMD_LOG_LEVEL",        "notice");
  // Which client networks count as "own" (skip external checks): the
  // production default treats RFC1918 as internal; the e2e stack
  // narrows this to loopback so the test-runner's mail is verified.
  v["RSPAMD_LOCAL_ADDRS"] = env_or(
      "RSPAMD_LOCAL_ADDRS",
      "192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8, 127.0.0.0/8, ::1");
  // Networks whose mail is DKIM-signed even without SASL auth (on top
  // of sign_local / sign_authenticated). dkim_signing expects a UCL
  // list — a bare CIDR string would be parsed as a map URL — so the
  // comma/space-separated env is rewritten to `"cidr", "cidr"` here.
  {
    std::string list;
    std::string item;
    std::istringstream in(env_or("RSPAMD_SIGN_NETWORKS", "127.0.0.0/8"));
    while (std::getline(in, item, ',')) {
      const auto begin = item.find_first_not_of(" \t");
      if (begin == std::string::npos) continue;
      const auto end = item.find_last_not_of(" \t");
      if (!list.empty()) list += ", ";
      list += "\"" + item.substr(begin, end - begin + 1) + "\"";
    }
    v["RSPAMD_SIGN_NETWORKS"] = list;
  }

  // Force-action rules shared by permissive and reject: a broken or
  // unknown-key DKIM signature is always a hard bounce (v2 contract:
  // DKIM is optional, but must be correct if published). DKIM_SIGNED
  // excludes our own outbound (it is stamped by dkim_signing when we
  // sign, i.e. for authenticated users and sign_networks members).
  const std::string force_bad_sig =
      "    DKIM_BAD_SIG_REJECT {\n"
      "        action = \"reject\";\n"
      "        expression = \"(R_DKIM_REJECT | R_DKIM_PERMFAIL) & !DKIM_SIGNED\";\n"
      "        message = \"message rejected: DKIM signature verification failed\";\n"
      "    }\n";
  const std::string force_missing_sig =
      "    DKIM_MISSING_REJECT {\n"
      "        action = \"reject\";\n"
      "        expression = \"!R_DKIM_ALLOW & !DKIM_SIGNED\";\n"
      "        message = \"message rejected: a valid DKIM signature is required\";\n"
      "    }\n";
  const std::string dmarc_reject_actions =
      "actions = {\n"
      "    reject = \"reject\";\n"
      "}\n";

  if (mode == "off") {
    v["RSPAMD_DKIM_ENABLED"]     = "false";
    v["RSPAMD_DMARC_ENABLED"]    = "false";
    v["RSPAMD_DMARC_ACTIONS"]    = "";
    v["RSPAMD_GREYLIST_ENABLED"] = "false";
    v["RSPAMD_FORCE_ACTIONS"]    = "";
    v["RSPAMD_ANTIVIRUS_ACTION"] = "";
  } else if (mode == "log") {
    v["RSPAMD_DKIM_ENABLED"]     = "true";
    v["RSPAMD_DMARC_ENABLED"]    = "true";
    v["RSPAMD_DMARC_ACTIONS"]    = "";
    v["RSPAMD_GREYLIST_ENABLED"] = "false";
    v["RSPAMD_FORCE_ACTIONS"]    = "";
    v["RSPAMD_ANTIVIRUS_ACTION"] = "";
    // log mode raises the reject threshold to a value no real mail
    // reaches, effectively downgrading `reject` action to `add header`.
    v["RSPAMD_REJECT_SCORE"]     = "999";
  } else if (mode == "permissive") {
    v["RSPAMD_DKIM_ENABLED"]     = "true";
    v["RSPAMD_DMARC_ENABLED"]    = "true";
    v["RSPAMD_DMARC_ACTIONS"]    = dmarc_reject_actions;
    v["RSPAMD_GREYLIST_ENABLED"] = "true";
    v["RSPAMD_FORCE_ACTIONS"]    = "rules {\n" + force_bad_sig + "}\n";
    v["RSPAMD_ANTIVIRUS_ACTION"] = "action = \"reject\";";
  } else if (mode == "reject") {
    v["RSPAMD_DKIM_ENABLED"]     = "true";
    v["RSPAMD_DMARC_ENABLED"]    = "true";
    v["RSPAMD_DMARC_ACTIONS"]    = dmarc_reject_actions;
    v["RSPAMD_GREYLIST_ENABLED"] = "true";
    // reject mode additionally bounces unsigned external mail.
    v["RSPAMD_FORCE_ACTIONS"] =
        "rules {\n" + force_bad_sig + force_missing_sig + "}\n";
    v["RSPAMD_ANTIVIRUS_ACTION"] = "action = \"reject\";";
  } else {
    throw std::runtime_error(
        "DKIM_DMARC must be one of: off, log, permissive, reject "
        "(got \"" + mode + "\")");
  }
  return v;
}

// --------------------------------------------------- healthcheck ----------

int
tcp_probe(const std::string &host, int port) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) return 1;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
  int rc = connect(s, reinterpret_cast<sockaddr *>(&addr), sizeof addr);
  close(s);
  return rc == 0 ? 0 : 1;
}

int
healthcheck() {
  // Both the milter proxy (11332) and the controller (11334) must be
  // reachable — if either is dead, restart the container.
  return tcp_probe("127.0.0.1", 11332) || tcp_probe("127.0.0.1", 11334);
}

} // namespace

int main(int argc, char *argv[]) try {
  if (argc > 1 && std::string(argv[1]) == "--healthcheck") return healthcheck();

  const std::string domains_env = env_or("DOMAINS", env_or("DOMAIN"));
  const std::vector<std::string> domains = split_ws(domains_env);
  if (domains.empty()) {
    std::cerr << "#### ERROR: set DOMAINS (space-separated) or DOMAIN "
                 "(single) so rspamd can sign outgoing mail" << std::endl;
    return 1;
  }
  const std::string selector = env_or("SELECTOR", "mail");
  const std::string mode     = env_or("DKIM_DMARC", "reject");

  // 1. Generate any missing DKIM keys; collect the notifications.
  std::vector<std::pair<std::string, std::string>> new_keys;
  for (const auto &d : domains) {
    std::string record;
    if (ensure_dkim_key(d, selector, record))
      new_keys.emplace_back(d, record);
  }

  // 2. E-mail the DNS records (best-effort, non-blocking).
  notify_new_keys(new_keys);

  // 3. Refresh the signing_table + key_table maps.
  write_dkim_maps(domains, selector);

  // 4. Stage /etc/rspamd/local.d/*.conf with mode-appropriate knobs.
  stage_configs(mode_variables(mode));

  std::cerr << "**** Starting rspamd in mode=" << mode
            << " on milter port 11332, controller 11334 for: "
            << domains_env << std::endl;

  const char *exec_argv[] = {"rspamd", "-f", nullptr};
  execv(RSPAMD, const_cast<char *const *>(exec_argv));
  std::perror(RSPAMD);
  return 1;
} catch (const std::exception &e) {
  std::cerr << "EXCEPTION: " << e.what() << std::endl;
  return 1;
} catch (...) {
  std::cerr << "UNKNOWN ERROR" << std::endl;
  return 1;
}
