-- Transport encryption transparency.
--
-- Postfix hands rspamd the live SMTP session's TLS version and cipher as
-- milter macros ({tls_version}, {cipher} — see the postfix image's
-- `milter_mail_macros`). This postfilter stamps a machine-readable
-- `X-Transport-Security` header on every incoming mail recording how the
-- LAST hop (the sending server → our MX) was encrypted:
--
--   X-Transport-Security: TLSv1.3 (cipher TLS_AES_256_GCM_SHA384)
--   X-Transport-Security: none    (the peer delivered in the clear)
--
-- Only the last hop is trustworthy — earlier Received headers are
-- written by foreign servers and can be forged — but that is exactly the
-- hop an operator can act on: warn the peers that still deliver without
-- (or with obsolete) TLS. Adding a header never breaks a DKIM signature
-- (signatures only cover the headers the signer enumerated in h=), so
-- this is safe on signed mail too.
--
-- The webmail (SnappyMail transport-security plugin) reads this header
-- and shows a red / orange marker for cleartext / obsolete transport.

local function macro(task, name)
  local h = task:get_request_header(name)
  if h then
    local s = tostring(h)
    if s and #s > 0 then return s end
  end
  return nil
end

rspamd_config:register_symbol({
  name = 'TRANSPORT_SECURITY_HEADER',
  type = 'postfilter',
  priority = 10,
  callback = function(task)
    local ver = macro(task, 'tls_version') or macro(task, 'TLS-Version')
    local ciph = macro(task, 'cipher') or macro(task, 'Cipher')
    local value
    if ver then
      value = ciph and (ver .. ' (cipher ' .. ciph .. ')') or ver
    else
      value = 'none'
    end
    -- Strip any incoming X-Transport-Security first: it is OUR header,
    -- so a sender-supplied one is a forgery attempt (a cleartext mail
    -- claiming `TLSv1.3` to hide from the webmail marker). remove_headers
    -- with count 0 drops every existing instance before we add the real
    -- last-hop value.
    --
    -- The X-Spam-* verdict headers need no equivalent here: upstream
    -- milter_headers already removes sender-supplied X-Spam-Flag /
    -- X-Spam-Status on every scan (and X-Spam-Level from score >= 1),
    -- and the SPAM_FLAG rule scores a pre-existing flag as a spam
    -- signal. Pinned by
    -- test_delivery_mode.py::test_forged_spam_headers_stripped_on_ingress.
    task:set_milter_reply({
      remove_headers = {
        ['X-Transport-Security'] = 0,
      },
      add_headers = {
        ['X-Transport-Security'] = { order = 1, value = value },
      },
    })
  end,
})
