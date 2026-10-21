FROM mwaeckerlin/very-base AS init
RUN $PKG_INSTALL g++
COPY init.cpp .
RUN g++ -static -Os -flto=auto -fno-rtti -ffunction-sections -fdata-sections \
        -Wl,--gc-sections -Wl,-s -std=c++20 -o init init.cpp
RUN strip -s -R .comment -R .gnu.version --strip-unneeded init

FROM mwaeckerlin/very-base AS build
RUN $PKG_INSTALL rspamd rspamd-controller rspamd-proxy rspamd-utils ca-certificates
RUN mkdir -p /etc/rspamd /etc/rspamd/local.d /etc/rspamd.d.template \
             /var/lib/rspamd/dkim /run/rspamd /tmp \
    && chmod 1777 /tmp \
    && chown -R rspamd:rspamd /etc/rspamd /var/lib/rspamd /run/rspamd
COPY rspamd.conf.local          /etc/rspamd/rspamd.conf.local
# Auto-included by the packaged rspamd.conf (`.include(try=true)
# "$CONFDIR/rspamd.local.lua"`): stamps the X-Transport-Security header
# from the SMTP session's TLS macros handed over by postfix.
COPY transport_security.lua     /etc/rspamd/rspamd.local.lua
COPY worker-proxy.inc           /etc/rspamd.d.template/worker-proxy.inc
COPY worker-controller.inc      /etc/rspamd.d.template/worker-controller.inc
COPY actions.conf               /etc/rspamd.d.template/actions.conf
COPY dkim.conf                  /etc/rspamd.d.template/dkim.conf
COPY dkim_signing.conf          /etc/rspamd.d.template/dkim_signing.conf
COPY dmarc.conf                 /etc/rspamd.d.template/dmarc.conf
COPY force_actions.conf         /etc/rspamd.d.template/force_actions.conf
COPY greylist.conf              /etc/rspamd.d.template/greylist.conf
COPY classifier-bayes.conf      /etc/rspamd.d.template/classifier-bayes.conf
COPY redis.conf                 /etc/rspamd.d.template/redis.conf
COPY antivirus.conf             /etc/rspamd.d.template/antivirus.conf
COPY milter_headers.conf        /etc/rspamd.d.template/milter_headers.conf
COPY options.inc                /etc/rspamd.d.template/options.inc
COPY logging.inc                /etc/rspamd.d.template/logging.inc
COPY --from=init init /usr/bin/init

# Collect only the binaries, shared libraries and configs the runtime
# actually needs into /root/. The final scratch stage copies /root/
# verbatim, so nothing not listed here (no shell, no package manager,
# no perl) ends up in the shipped image.
RUN tar cph \
        /etc/rspamd /etc/rspamd.d.template /var/lib/rspamd /run/rspamd /tmp \
        /etc/passwd /etc/group /etc/nsswitch.conf \
        /etc/ssl/certs /etc/ssl/cert.pem /usr/share/ca-certificates \
        /usr/bin/rspamd /usr/bin/rspamadm /usr/bin/init \
        /usr/lib/rspamd \
        /usr/share/rspamd \
        /usr/share/icu \
        $(for f in /usr/bin/rspamd /usr/bin/rspamadm /usr/lib/rspamd/*.so; do \
              ldd "$f" 2>/dev/null | sed -n 's,.* => \([^ ]*\) .*,\1,p'; \
          done | sort -u) \
    | tar xpC /root/

FROM mwaeckerlin/scratch
ENV CONTAINERNAME="rspamd" \
    DOMAIN="" \
    DOMAINS="" \
    SELECTOR="mail" \
    AUTHSERV_ID="" \
    DKIM_DMARC="reject" \
    NOTIFY_EMAIL="" \
    NOTIFY_SMTP="127.0.0.1:25" \
    REDIS_HOST="redis" \
    REDIS_PORT="6379" \
    CLAMAV_HOST="clamav" \
    CLAMAV_PORT="3310"
# Controller (web UI, rspamc): networks with password-free privileged
# access, and an optional password for everyone else.
ENV RSPAMD_CONTROLLER_SECURE_IP="127.0.0.0/8, ::1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16" \
    RSPAMD_CONTROLLER_PASSWORD=""
ENV RSPAMD_PROXY_WORKERS="4" \
    RSPAMD_BAYES_MIN_LEARNS="200" \
    RSPAMD_MAX_MESSAGE="50Mb"
EXPOSE 11332 11334
VOLUME /var/lib/rspamd
USER rspamd
ENTRYPOINT ["/usr/bin/init"]
COPY --from=build /root/ /
