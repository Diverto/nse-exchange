local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local rand = require "rand"

description = [[
Checks for specific Exchange 0-day vuln: CVE-2022-41082
(if virtual patching succeeded)

The script will follow up to 5 HTTP redirects, using the default rules in the
http library.
]]

---
--@args http-cve-2022-41082.url     The url to fetch. Default: /
--      http-cve-2022-41082.method  method to fetch. Default: GET
--@output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | http-vuln-cve2022-41082:
-- |   VULNERABLE:
-- |   Microsoft Exchange - 0-day RCE
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2022-41082
-- |     Risk factor: High  CVSSv2: 10.0 (HIGH) (AV:N/AC:L/AU:N/C:C/I:C/A:C)
-- |       Exchange 0-day vuln: CVE-2022-41082
-- |
-- |     Disclosure date: 2022-09-29
-- |     References:
-- |       https://www.microsoft.com/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/
-- |       https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/
-- |       https://microsoft.github.io/CSS-Exchange/Security/EOMTv2/
-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-41082
--

author = "Vlatko Kosturjak"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local resp, redirect_url, title

  local basepath = stdnse.get_script_args(SCRIPT_NAME..".url")
  local method = string.upper(stdnse.get_script_args(SCRIPT_NAME..".method") or "GET")

  local vuln = {
    title = "Microsoft Exchange - 0-day RCE",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    scores = {
      CVSSv2 = "10.0 (HIGH) (AV:N/AC:L/AU:N/C:C/I:C/A:C)",
    },
    description = [[
Exchange 0-day vuln: CVE-2022-41082
    ]],
    IDS = {CVE = "CVE-2022-41082"},
    references = {
      'https://www.microsoft.com/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/',
      'https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/',
      'https://microsoft.github.io/CSS-Exchange/Security/EOMTv2/'
    },
    dates = { disclosure = { year = '2022', month = '09', day = '29' } }
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  if not basepath then
    basepath = "/"
  end

  path = basepath .. 'autodiscover/autodiscover.json@Powershell.'..rand.random_alpha(10)..'.com/owa/'

  target = host.ip .. "-" .. port.number

  stdnse.debug1("Final path: "..path)

  local request_opts = {
    header = {
      Connection = "close"
    },
    bypass_cache = true,
    no_cache = true
  }

  resp = http.get( host, port, path, request_opts )
  -- check for a redirect
  if resp.location then
    redirect_url = resp.location[#resp.location]
    if resp.status and tostring( resp.status ):match( "30%d" ) then
      return {redirect_url = redirect_url}, ("Did not follow redirect to %s"):format( redirect_url )
    end
  end

  local response = http.generic_request( host, port, method, path, { no_cache = true } )

  if response.status and response.status == 401 then
    -- X-OWA-Version
    if response.header['x-owa-version'] then
      vuln.state = vulns.STATE.VULN
    else
      vuln.state = vulns.STATE.LIKELY_VULN
    end
  end

  return vuln_report:make_output(vuln)
end
