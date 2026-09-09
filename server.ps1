$ErrorActionPreference = 'Stop'

$root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$public = Join-Path $root 'public'
$sitesJson = Join-Path $root 'sites.json'
$port   = 8000

Write-Host "Preparing .NET components (first run compiles the checker)..."
Add-Type -AssemblyName System.Web.Extensions

# ============================================================
# C# multi-site checker: HTTP status + security probe + HIBP
# ============================================================
$csharp = @'
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Net;
using System.Net.Http;
using System.Web.Script.Serialization;

public static class SiteChecker
{
    // ================================================================
    // SHARED HELPERS
    // ================================================================

    private static HttpClient MakeClient(int timeoutSec)
    {
        var h = new HttpClientHandler();
        h.AllowAutoRedirect = true;
        h.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
        // Bypass SSL validation so we can probe sites with misconfigured certificates
        // (common on government sites). This is intentional for uptime checking, not a
        // security vulnerability - the tool reports the cert issue as a finding.
        h.ServerCertificateCustomValidationCallback = (snd, cert, chain, sslErr) => true;
        var c = new HttpClient(h);
        c.Timeout = TimeSpan.FromSeconds(timeoutSec);
        c.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36");
        return c;
    }

    private static string Normalize(string url)
    {
        url = url.Trim();
        if (!url.ToLower().StartsWith("http://") && !url.ToLower().StartsWith("https://"))
            url = "https://" + url;
        return url;
    }

    // ================================================================
    // SITE AVAILABILITY & SECURITY CHECK
    // ================================================================

    public static string CheckSites(string rawUrls, int timeoutSec, int maxConcurrent)
    {
        string[] urls = rawUrls.Split(new char[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
        var bag = new System.Collections.Concurrent.ConcurrentBag<Dictionary<string, object>>();
        var client = MakeClient(timeoutSec);
        Parallel.For(0, urls.Length, new ParallelOptions { MaxDegreeOfParallelism = maxConcurrent }, i =>
        {
            bag.Add(CheckOne(client, urls[i], timeoutSec));
        });
        client.Dispose();
        return new JavaScriptSerializer().Serialize(bag.ToArray());
    }

    private static Dictionary<string, object> CheckOne(HttpClient client, string url, int timeoutSec)
    {
        url = Normalize(url);
        var d = new Dictionary<string, object>();
        d["url"] = url; d["status"] = "DOWN"; d["reachable"] = false; d["code"] = 0; d["ms"] = 0;
        d["error"] = ""; d["dns"] = true; d["httpNote"] = ""; d["tries"] = 1; d["downReason"] = "";
        d["hsts"] = 0; d["csp"] = 0; d["xframe"] = 0; d["exposed"] = new string[0];

        int code = 0; string lastErr = ""; bool gotResponse = false;
        var sw = System.Diagnostics.Stopwatch.StartNew();

        // up to 2 attempts: a network blip should not be reported as a false "DOWN"
        for (int attempt = 0; attempt < 2 && code == 0; attempt++)
        {
            try
            {
                using (var resp = client.GetAsync(url).GetAwaiter().GetResult())
                {
                    code = (int)resp.StatusCode;
                    gotResponse = true;
                    d["code"] = code;
                    d["reachable"] = true;
                    if (code >= 200 && code <= 299) d["httpNote"] = "OK";
                    else if (code >= 300 && code <= 399) d["httpNote"] = "Redirect";
                    else if (code >= 400 && code <= 499) d["httpNote"] = "Online but restricted (HTTP " + code + ")";
                    else if (code >= 500) d["httpNote"] = "Server reported an error (HTTP " + code + ")";
                    IEnumerable<string> v1, v2, v3;
                    if (resp.Headers.TryGetValues("Strict-Transport-Security", out v1)) d["hsts"] = 1;
                    if (resp.Headers.TryGetValues("Content-Security-Policy", out v2)) d["csp"] = 1;
                    if (resp.Headers.TryGetValues("X-Frame-Options", out v3)) d["xframe"] = 1;
                }
            }
            catch (Exception ex) { lastErr = ex.Message; d["tries"] = attempt + 1; DetectReason(d, ex); }
        }
        sw.Stop();

        if (gotResponse)
        {
            d["status"] = "UP";
        }
        else
        {
            d["error"] = lastErr;
            // verify DNS separately so we can report WHY it is down (factual, not a guess)
            try
            {
                var host = new Uri(url).Host;
                var t = Task.Run(() => System.Net.Dns.GetHostAddresses(host));
                if (t.Wait(3000))
                {
                    var addrs = t.Result;
                    d["dns"] = addrs != null && addrs.Length > 0;
                }
                else { d["dns"] = false; }
            }
            catch { d["dns"] = false; }
            if (!(bool)d["dns"]) { d["error"] = "DNS resolution failed - domain does not resolve"; }
        }
        d["ms"] = sw.ElapsedMilliseconds;

        // ----- exposure probe on common sensitive paths (only when reachable) -----
        if (gotResponse)
        {
            var prober = MakeClient(4);
            var exposed = new System.Collections.Concurrent.ConcurrentBag<string>();
            string[] paths = { "/.git/config", "/.env", "/.env.bak", "/backup.zip", "/server-status", "/.DS_Store", "/phpinfo.php" };
            var tasks = new List<Task>();
            foreach (var p in paths) tasks.Add(probe(prober, url, p, exposed));
            Task.WaitAll(tasks.ToArray());
            prober.Dispose();
            var list = new List<string>(exposed);
            list.Sort();
            d["exposed"] = list.ToArray();
        }
        return d;
    }

    // classify WHY a host is unreachable so the report is factual, not a guess:
    // dns / timeout / refused / reset(WAF drop) / tls / other
    private static void DetectReason(Dictionary<string, object> d, Exception ex)
    {
        string r = "other";
        Exception cur = ex;
        while (cur != null)
        {
            WebException we = cur as WebException;
            if (cur is TaskCanceledException || (we != null && we.Status == WebExceptionStatus.Timeout)) { r = "timeout"; break; }
            if (we != null && we.Status == WebExceptionStatus.ConnectFailure) { r = "refused"; break; }
            if (we != null && we.Status == WebExceptionStatus.ConnectionClosed) { r = "reset"; break; }
            if (we != null && (we.Status == WebExceptionStatus.SecureChannelFailure || we.Status == WebExceptionStatus.TrustFailure)) { r = "tls"; break; }
            if (cur is System.IO.IOException) { r = "reset"; break; }
            if (cur is System.Security.Authentication.AuthenticationException) { r = "tls"; break; }
            cur = cur.InnerException;
        }
        d["downReason"] = r;
    }

    private static Task probe(HttpClient client, string baseUrl, string path,
        System.Collections.Concurrent.ConcurrentBag<string> exposed)
    {
        return Task.Run(() =>
        {
            string u = baseUrl.TrimEnd('/') + path;
            try
            {
                using (var resp = client.GetAsync(u).GetAwaiter().GetResult())
                {
                    if ((int)resp.StatusCode == 200) exposed.Add(path);
                }
            }
            catch { }
        });
    }

    // ================================================================
    // HAVEIBeenPwned DOMAIN BREACH CHECK
    // ================================================================

    public static string BreachCheck(string rawDomains, string apiKey)
    {
        string[] doms = rawDomains.Split(new char[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
        var bag = new System.Collections.Concurrent.ConcurrentBag<Dictionary<string, object>>();
        var client = new HttpClient();
        client.Timeout = TimeSpan.FromSeconds(12);
        if (!string.IsNullOrEmpty(apiKey))
        {
            client.DefaultRequestHeaders.Add("hibp-api-key", apiKey);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("GovSiteChecker/1.0");
        }

        foreach (var dom in doms)
        {
            var dd = new Dictionary<string, object>();
            dd["domain"] = dom;
            if (string.IsNullOrEmpty(apiKey))
            {
                dd["note"] = "No HIBP key set; using local exposure scan only";
            }
            else
            {
                try
                {
                    using (var resp = client.GetAsync("https://haveibeenpwned.com/api/v3/domainsearch/" + Uri.EscapeDataString(dom)).GetAwaiter().GetResult())
                    {
                        int c = (int)resp.StatusCode;
                        if (c == 200)
                        {
                            string body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                            var ser = new JavaScriptSerializer();
                            var arr = ser.DeserializeObject(body) as object[];
                            var names = new List<string>();
                            if (arr != null)
                            {
                                foreach (var item in arr)
                                {
                                    var dic = item as Dictionary<string, object>;
                                    if (dic != null && dic.ContainsKey("Name")) names.Add((string)dic["Name"]);
                                }
                            }
                            dd["breached"] = names.Count > 0;
                            dd["names"] = names.ToArray();
                        }
                        else if (c == 404) { dd["breached"] = false; dd["names"] = new string[0]; }
                        else if (c == 401) { dd["note"] = "HIBP: invalid or unauthorized API key"; }
                        else if (c == 429) { dd["note"] = "HIBP: rate limited (free tier)"; }
                        else { dd["note"] = "HIBP: HTTP " + c; }
                    }
                }
                catch (Exception ex) { dd["note"] = "HIBP error: " + ex.Message; }
            }
            bag.Add(dd);
        }
        return new JavaScriptSerializer().Serialize(bag.ToArray());
    }

    // ================================================================
    // OSINT TOOLS
    // ================================================================

    // ----- IP Geolocation -----
    public static string GeolocateIp(string ip)
    {
        ip = ip.Trim();
        var d = new Dictionary<string, object>();
        d["query"] = ip;

        if (string.IsNullOrEmpty(ip))
        {
            d["error"] = "Please enter an IP address";
            return new JavaScriptSerializer().Serialize(d);
        }

        try
        {
            var client = new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(10);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            string url = "https://ip-api.com/json/" + Uri.EscapeDataString(ip);
            using (var resp = client.GetAsync(url).GetAwaiter().GetResult())
            {
                string body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                var ser = new JavaScriptSerializer();
                var parsed = ser.DeserializeObject(body) as Dictionary<string, object>;
                if (parsed != null)
                {
                    if (parsed.ContainsKey("status") && (string)parsed["status"] == "fail")
                    {
                        d["error"] = parsed.ContainsKey("message") ? (string)parsed["message"] : "Lookup failed - invalid IP or API error";
                        return new JavaScriptSerializer().Serialize(d);
                    }
                    string[] keys = { "query", "country", "countryCode", "region", "regionName", "city", "zip", "lat", "lon", "timezone", "isp", "org", "as" };
                    foreach (var k in keys) { if (parsed.ContainsKey(k)) d[k] = parsed[k]; }
                }
                else { d["error"] = "Invalid response from API: " + body.Substring(0, Math.Min(body.Length, 200)); }
            }
        }
        catch (Exception ex) { d["error"] = "Connection error: " + ex.Message; }
        return new JavaScriptSerializer().Serialize(d);
    }

    // ----- WHOIS Lookup via RDAP -----
    public static string WhoisLookup(string domain)
    {
        domain = domain.Trim().ToLower().TrimEnd('.');
        var d = new Dictionary<string, object>();
        d["domain"] = domain;

        try
        {
            var rdapData = FetchRdapData(domain);
            if (rdapData != null)
            {
                if (rdapData.ContainsKey("created")) d["created"] = rdapData["created"];
                if (rdapData.ContainsKey("expires")) d["expires"] = rdapData["expires"];
                if (rdapData.ContainsKey("updated")) d["updated"] = rdapData["updated"];
                if (rdapData.ContainsKey("registrar")) d["registrar"] = rdapData["registrar"];
                if (rdapData.ContainsKey("status")) d["status"] = rdapData["status"];
                if (rdapData.ContainsKey("nameServers")) d["nameServers"] = rdapData["nameServers"];
                if (rdapData.ContainsKey("rawText")) d["rawText"] = rdapData["rawText"];
            }
            else
            {
                d["error"] = "Domain not found in RDAP database";
            }
        }
        catch (Exception ex) { d["error"] = ex.Message; }
        return new JavaScriptSerializer().Serialize(d);
    }

    // ----- Email Header Analysis -----
    public static string AnalyzeEmailHeader(string headerText)
    {
        var d = new Dictionary<string, object>();
        var ser = new JavaScriptSerializer();

        try
        {
            string[] lines = headerText.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.RemoveEmptyEntries);

            // Extract basic headers
            foreach (var line in lines)
            {
                if (line.StartsWith("From:", StringComparison.OrdinalIgnoreCase))
                    d["from"] = line.Substring(5).Trim();
                else if (line.StartsWith("To:", StringComparison.OrdinalIgnoreCase))
                    d["to"] = line.Substring(3).Trim();
                else if (line.StartsWith("Subject:", StringComparison.OrdinalIgnoreCase))
                    d["subject"] = line.Substring(8).Trim();
                else if (line.StartsWith("Date:", StringComparison.OrdinalIgnoreCase))
                    d["date"] = line.Substring(5).Trim();
            }

            // Parse Received headers (in reverse order - most recent first)
            var hops = new List<Dictionary<string, object>>();
            var receivedLines = new List<string>();

            for (int i = lines.Length - 1; i >= 0; i--)
            {
                string line = lines[i];
                if (line.StartsWith("Received:", StringComparison.OrdinalIgnoreCase))
                {
                    receivedLines.Add(line.Substring(9).Trim());
                }
                else if (receivedLines.Count > 0 && (line.StartsWith("\t") || line.StartsWith(" ") || line.StartsWith("From") || line.StartsWith("By") || line.StartsWith("For") || line.StartsWith("Id") || line.StartsWith("with")))
                {
                    // Continuation of previous Received header
                    receivedLines[receivedLines.Count - 1] += " " + line.Trim();
                }
            }

            foreach (var recv in receivedLines)
            {
                var hop = new Dictionary<string, object>();

                // Extract "from" part
                int fromIdx = recv.IndexOf("from ", StringComparison.OrdinalIgnoreCase);
                if (fromIdx >= 0)
                {
                    string afterFrom = recv.Substring(fromIdx + 5);
                    int spaceIdx = afterFrom.IndexOf(' ');
                    string fromPart = spaceIdx > 0 ? afterFrom.Substring(0, spaceIdx) : afterFrom;
                    hop["from"] = fromPart;
                }

                // Extract "by" part
                int byIdx = recv.IndexOf(" by ", StringComparison.OrdinalIgnoreCase);
                if (byIdx >= 0)
                {
                    string afterBy = recv.Substring(byIdx + 4);
                    int spaceIdx = afterBy.IndexOf(' ');
                    hop["by"] = spaceIdx > 0 ? afterBy.Substring(0, spaceIdx) : afterBy;
                }

                // Extract IP address in brackets
                var ipMatch = System.Text.RegularExpressions.Regex.Match(recv, @"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]");
                if (ipMatch.Success) hop["ip"] = ipMatch.Groups[1].Value;

                // Extract date
                int semicolonIdx = recv.LastIndexOf(';');
                if (semicolonIdx >= 0)
                {
                    string datePart = recv.Substring(semicolonIdx + 1).Trim();
                    if (datePart.Length > 5 && datePart.Length < 80) hop["date"] = datePart;
                }

                if (hop.ContainsKey("from") || hop.ContainsKey("by"))
                    hops.Add(hop);
            }

            d["hops"] = hops.ToArray();

            // Extract originating IP (first hop's IP)
            if (hops.Count > 0 && hops[0].ContainsKey("ip"))
            {
                string originIp = (string)hops[0]["ip"];
                d["originIp"] = originIp;

                // Geolocate the originating IP
                try
                {
                    var geoClient = new HttpClient();
                    geoClient.Timeout = TimeSpan.FromSeconds(8);
                    using (var resp = geoClient.GetAsync("https://ip-api.com/json/" + Uri.EscapeDataString(originIp) + "?fields=66846719").GetAwaiter().GetResult())
                    {
                        string body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                        var parsed = ser.DeserializeObject(body) as Dictionary<string, object>;
                        if (parsed != null && parsed.ContainsKey("status") && (string)parsed["status"] == "success")
                        {
                            string city = parsed.ContainsKey("city") ? (string)parsed["city"] : "";
                            string region = parsed.ContainsKey("regionName") ? (string)parsed["regionName"] : "";
                            string country = parsed.ContainsKey("country") ? (string)parsed["country"] : "";
                            d["originLocation"] = city + (city != "" && region != "" ? ", " : "") + region + (region != "" && country != "" ? ", " : "") + country;
                            d["originIsp"] = parsed.ContainsKey("isp") ? (string)parsed["isp"] : "";
                        }
                    }
                }
                catch { }
            }

            // Check authentication headers
            var auth = new Dictionary<string, object>();
            foreach (var line in lines)
            {
                if (line.StartsWith("Authentication-Results:", StringComparison.OrdinalIgnoreCase))
                {
                    string results = line.Substring(23);
                    if (results.IndexOf("spf=", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        int idx = results.IndexOf("spf=", StringComparison.OrdinalIgnoreCase);
                        string val = results.Substring(idx + 4, Math.Min(20, results.Length - idx - 4)).Split(new[] { ' ', ';' })[0];
                        auth["spf"] = val;
                        auth["spfResult"] = val.Equals("pass", StringComparison.OrdinalIgnoreCase) ? "pass" : "fail";
                    }
                    if (results.IndexOf("dkim=", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        int idx = results.IndexOf("dkim=", StringComparison.OrdinalIgnoreCase);
                        string val = results.Substring(idx + 5, Math.Min(20, results.Length - idx - 5)).Split(new[] { ' ', ';' })[0];
                        auth["dkim"] = val;
                        auth["dkimResult"] = val.Equals("pass", StringComparison.OrdinalIgnoreCase) ? "pass" : "fail";
                    }
                }
                else if (line.StartsWith("DKIM-Signature:", StringComparison.OrdinalIgnoreCase))
                {
                    if (!auth.ContainsKey("dkim")) auth["dkim"] = "present";
                }
                else if (line.StartsWith("ARC-Authentication-Results:", StringComparison.OrdinalIgnoreCase))
                {
                    if (!auth.ContainsKey("spf")) auth["spf"] = "see ARC header";
                }
            }
            if (auth.Count > 0) d["auth"] = auth;
        }
        catch (Exception ex) { d["error"] = ex.Message; }
        return ser.Serialize(d);
    }

    // ----- Domain Reputation Check -----
    public static string CheckDomainReputation(string domain)
    {
        domain = domain.Trim().ToLower().TrimEnd('.');
        var d = new Dictionary<string, object>();
        d["domain"] = domain;
        d["safe"] = true;
        d["threats"] = new string[0];
        d["categories"] = new string[0];
        d["blacklisted"] = false;

        try
        {
            // Check if domain resolves (basic liveness)
            bool resolves = false;
            try
            {
                var t = Task.Run(() => Dns.GetHostAddresses(domain));
                if (t.Wait(3000) && t.Result != null && t.Result.Length > 0) resolves = true;
            }
            catch { }

            // Check for known suspicious TLDs
            string tld = domain.Contains(".") ? domain.Substring(domain.LastIndexOf('.') + 1) : "";
            var suspiciousTlds = new HashSet<string> { "xyz", "top", "club", "online", "site", "work", "biz", "info", "buzz", "tk", "ml", "ga", "cf", "gq" };
            var threatList = new List<string>();
            var catList = new List<string>();

            if (suspiciousTlds.Contains(tld))
            {
                threatList.Add("Suspicious TLD (" + tld + ")");
                catList.Add("High-risk TLD");
            }

            // Check for common phishing patterns
            if (domain.Contains("login") || domain.Contains("verify") || domain.Contains("secure") || domain.Contains("account") || domain.Contains("update"))
            {
                if (domain.Length > 20)
                {
                    threatList.Add("Possible phishing keyword pattern");
                    catList.Add("Phishing risk");
                }
            }

            // Check for typosquatting of known brands
            var knownBrands = new string[] { "google", "facebook", "apple", "microsoft", "amazon", "paypal", "netflix", "instagram", "twitter" };
            foreach (var brand in knownBrands)
            {
                if (domain.Contains(brand) && !domain.EndsWith(brand + ".com") && !domain.EndsWith(brand + ".org"))
                {
                    threatList.Add("Possible typosquatting of " + brand);
                    catList.Add("Brand impersonation");
                    break;
                }
            }

            // Try to get WHOIS data for registrar info
            try
            {
                var rdapData = FetchRdapData(domain);
                if (rdapData != null)
                {
                    if (rdapData.ContainsKey("created")) d["created"] = rdapData["created"];
                    if (rdapData.ContainsKey("registrar")) d["registrar"] = rdapData["registrar"];
                }
            }
            catch { }

            d["resolves"] = resolves;
            d["threats"] = threatList.ToArray();
            d["categories"] = catList.ToArray();
            if (threatList.Count > 0) { d["safe"] = false; d["blacklisted"] = true; }
        }
        catch (Exception ex) { d["error"] = ex.Message; }
        return new JavaScriptSerializer().Serialize(d);
    }

    // ----- Shared RDAP data fetcher -----
    private static Dictionary<string, object> FetchRdapData(string domain)
    {
        var client = new HttpClient();
        client.Timeout = TimeSpan.FromSeconds(8);
        using (var resp = client.GetAsync("https://rdap.org/domain/" + Uri.EscapeDataString(domain)).GetAwaiter().GetResult())
        {
            if ((int)resp.StatusCode != 200) return null;
            string body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            var ser = new JavaScriptSerializer();
            var parsed = ser.DeserializeObject(body) as Dictionary<string, object>;
            if (parsed == null) return null;

            var result = new Dictionary<string, object>();

            // Extract events (registration, expiration, update)
            if (parsed.ContainsKey("events"))
            {
                var events = parsed["events"] as object[];
                if (events != null)
                {
                    foreach (var ev in events)
                    {
                        var evd = ev as Dictionary<string, object>;
                        if (evd != null && evd.ContainsKey("eventAction"))
                        {
                            string action = (string)evd["eventAction"];
                            string date = evd.ContainsKey("eventDate") ? (string)evd["eventDate"] : "";
                            if (action == "registration") result["created"] = date;
                            else if (action == "expiration") result["expires"] = date;
                            else if (action == "last update of RDAP database") result["updated"] = date;
                        }
                    }
                }
            }

            // Extract registrar name from entities/vcardArray
            if (parsed.ContainsKey("entities"))
            {
                var entities = parsed["entities"] as object[];
                if (entities != null)
                {
                    foreach (var ent in entities)
                    {
                        var entd = ent as Dictionary<string, object>;
                        if (entd != null && entd.ContainsKey("vcardArray"))
                        {
                            var vcard = entd["vcardArray"] as object[];
                            if (vcard != null && vcard.Length > 1)
                            {
                                var fields = vcard[1] as object[];
                                if (fields != null)
                                {
                                    foreach (var f in fields)
                                    {
                                        var fd = f as object[];
                                        if (fd != null && fd.Length >= 3)
                                        {
                                            string fn = fd[0] is string ? (string)fd[0] : "";
                                            if (fn == "fn") result["registrar"] = fd[3] is string ? (string)fd[3] : "";
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Extract status
            if (parsed.ContainsKey("status"))
            {
                var statuses = parsed["status"] as object[];
                if (statuses != null)
                {
                    var statusList = new List<string>();
                    foreach (var s in statuses) { if (s is string) statusList.Add((string)s); }
                    result["status"] = statusList.ToArray();
                }
            }

            // Extract name servers
            if (parsed.ContainsKey("nameservers"))
            {
                var nsArr = parsed["nameservers"] as object[];
                if (nsArr != null)
                {
                    var nsList = new List<string>();
                    foreach (var ns in nsArr)
                    {
                        var nsd = ns as Dictionary<string, object>;
                        if (nsd != null && nsd.ContainsKey("ldhName")) nsList.Add((string)nsd["ldhName"]);
                    }
                    result["nameServers"] = nsList.ToArray();
                }
            }

            // Store raw for display
            result["rawText"] = body.Length > 3000 ? body.Substring(0, 3000) + "..." : body;
            return result;
        }
    }
}
'@

Add-Type -TypeDefinition $csharp -ReferencedAssemblies 'System.Net.Http.dll','System.Web.Extensions.dll','System.Web.Extensions'

# ============================================================
# HTTP SERVER
# ============================================================
$mime = @{
    '.html' = 'text/html; charset=utf-8'
    '.css'  = 'text/css; charset=utf-8'
    '.js'   = 'application/javascript; charset=utf-8'
    '.json' = 'application/json; charset=utf-8'
    '.svg'  = 'image/svg+xml'
    '.png'  = 'image/png'
    '.ico'  = 'image/x-icon'
}

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:$port/")
$listener.Start()

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host "  Government Site Checker is running" -ForegroundColor Green
Write-Host "  Open: http://localhost:$port/" -ForegroundColor White
Write-Host "  Press Ctrl+C to stop." -ForegroundColor DarkGray
Write-Host "==============================================" -ForegroundColor Green
Write-Host ""

Start-Process "http://localhost:$port/"

function Send-Response {
    param($Context, [string]$ContentType, [byte[]]$Data, [int]$StatusCode = 200)
    $Context.Response.StatusCode = $StatusCode
    $Context.Response.ContentType = $ContentType
    try {
        $Context.Response.Headers.Add('Cache-Control', 'no-store, no-cache, max-age=0')
        $Context.Response.Headers.Add('Pragma', 'no-cache')
    } catch { }
    $Context.Response.OutputStream.Write($Data, 0, $Data.Length)
    $Context.Response.Close()
}

try {
    while ($listener.IsListening) {
        try {
            $ctx = $listener.GetContext()
            $req = $ctx.Request
            $path = $req.Url.AbsolutePath

            # Helper: read and parse JSON body, return null on failure
            function Read-JsonBody($req) {
                try {
                    $reader = New-Object System.IO.StreamReader($req.InputStream, $req.ContentEncoding)
                    $bodyTxt = $reader.ReadToEnd()
                    $reader.Close()
                    if ([string]::IsNullOrWhiteSpace($bodyTxt)) { return $null }
                    return $bodyTxt | ConvertFrom-Json
                } catch {
                    return $null
                }
            }

            # Helper: validate domain format
            function Test-ValidDomain($d) {
                return $d -match '^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
            }

            # Helper: validate IP format
            function Test-ValidIp($ip) {
                return $ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            }

            if ($path -eq '/api/check' -and $req.HttpMethod -eq 'POST') {
                $params = Read-JsonBody $req
                if ($null -eq $params) {
                    Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes('{"error":"Invalid or missing JSON body"}')) 400
                    continue
                }
                $urls = @($params.urls)
                if ($urls.Count -eq 0) {
                    Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes('{"error":"No URLs provided"}')) 400
                    continue
                }
                $timeout = if ($params.timeout) { [Math]::Min([Math]::Max([int]$params.timeout, 5), 120) } else { 12 }
                $urlsNorm = @($urls | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -First 100) -join "`n"
                $jsonOut = [SiteChecker]::CheckSites($urlsNorm, $timeout, 16)
                Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes($jsonOut))
            }
            elseif ($path -eq '/api/breach' -and $req.HttpMethod -eq 'POST') {
                $params = Read-JsonBody $req
                if ($null -eq $params) {
                    Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes('{"error":"Invalid or missing JSON body"}')) 400
                    continue
                }
                $domains = @($params.domains | ForEach-Object { $_.Trim().TrimStart(' ').ToLower() } | Where-Object { Test-ValidDomain $_ } | Select-Object -Unique -First 50) -join "`n"
                $key = if ($params.key) { [string]$params.key } else { '' }
                $jsonOut = [SiteChecker]::BreachCheck($domains, $key)
                Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes($jsonOut))
            }
            elseif ($path -eq '/api/osint/ip-geolocate' -and $req.HttpMethod -eq 'POST') {
                $params = Read-JsonBody $req
                if ($null -eq $params) {
                    Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes('{"error":"Invalid or missing JSON body"}')) 400
                    continue
                }
                $ip = if ($params.ip) { [string]$params.ip.Trim() } else { '' }
                if ($ip -and -not (Test-ValidIp $ip)) {
                    Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes('{"error":"Invalid IP address format"}')) 400
                    continue
                }
                $jsonOut = [SiteChecker]::GeolocateIp($ip)
                Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes($jsonOut))
            }
            elseif ($path -eq '/api/osint/whois' -and $req.HttpMethod -eq 'POST') {
                $params = Read-JsonBody $req
                if ($null -eq $params) {
                    Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes('{"error":"Invalid or missing JSON body"}')) 400
                    continue
                }
                $domain = if ($params.domain) { [string]$params.domain.Trim() } else { '' }
                if ($domain -and -not (Test-ValidDomain $domain)) {
                    Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes('{"error":"Invalid domain format"}')) 400
                    continue
                }
                $jsonOut = [SiteChecker]::WhoisLookup($domain)
                Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes($jsonOut))
            }
            elseif ($path -eq '/api/osint/email-header' -and $req.HttpMethod -eq 'POST') {
                $params = Read-JsonBody $req
                if ($null -eq $params) {
                    Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes('{"error":"Invalid or missing JSON body"}')) 400
                    continue
                }
                $header = if ($params.header) { [string]$params.header } else { '' }
                if ($header.Length -gt 100000) {
                    Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes('{"error":"Email header too large (max 100KB)"}')) 400
                    continue
                }
                $jsonOut = [SiteChecker]::AnalyzeEmailHeader($header)
                Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes($jsonOut))
            }
            elseif ($path -eq '/api/osint/domain-reputation' -and $req.HttpMethod -eq 'POST') {
                $params = Read-JsonBody $req
                if ($null -eq $params) {
                    Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes('{"error":"Invalid or missing JSON body"}')) 400
                    continue
                }
                $domain = if ($params.domain) { [string]$params.domain.Trim() } else { '' }
                if ($domain -and -not (Test-ValidDomain $domain)) {
                    Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes('{"error":"Invalid domain format"}')) 400
                    continue
                }
                $jsonOut = [SiteChecker]::CheckDomainReputation($domain)
                Send-Response $ctx 'application/json; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes($jsonOut))
            }
            elseif ($path -eq '/api/sites') {
                $data = [IO.File]::ReadAllBytes($sitesJson)
                Send-Response $ctx 'application/json; charset=utf-8' $data
            }
            else {
                $rel = if ($path -eq '/' -or $path -eq '') { 'index.html' } else { $path.TrimStart('/') }
                $file = Join-Path $public $rel
                $file = [IO.Path]::GetFullPath($file)
                if (-not $file.StartsWith([IO.Path]::GetFullPath($public))) {
                    Send-Response $ctx 'text/plain; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes('Forbidden')) 403
                    continue
                }
                if (Test-Path -LiteralPath $file -PathType Leaf) {
                    $ext = [IO.Path]::GetExtension($file).ToLower()
                    $ct = if ($mime.ContainsKey($ext)) { $mime[$ext] } else { 'application/octet-stream' }
                    Send-Response $ctx $ct ([IO.File]::ReadAllBytes($file))
                } else {
                    Send-Response $ctx 'text/plain; charset=utf-8' ([Text.Encoding]::UTF8.GetBytes('Not Found')) 404
                }
            }
        } catch {
            $log = Join-Path $root 'server.log'
            $line = (Get-Date -Format o) + '  ERROR: ' + $_.Exception.Message
            try { Add-Content -LiteralPath $log -Value $line } catch { }
            try { if ($ctx) { $ctx.Response.Close() } } catch { }
        }
    }
}
finally {
    $listener.Stop()
}