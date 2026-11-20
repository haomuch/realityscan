// Cloudflare 官方 IPv4 CIDR 网段
const CF_CIDRS = [
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
  "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
  "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
  "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
];

// 在中国大陆拥有 CDN 节点的大厂及云默认域名关键字黑名单
const BIG_TECH_KEYWORDS = [
  "microsoft", "azure", "msn.com", "live.com", "office.com", "windows", "bing.com", "xbox",
  "apple.com", "icloud", "akadns", "akamai", "akamaiedge", "akamaitechnologies",
  "amazonaws", "awsglobalconfig", "cloudfront", "fastly",
  "google", "gstatic", "googleapis", "1e100.net", "googleusercontent",
  "alibaba", "aliyun", "alicdn", "taobao", "tmall",
  "tencent", "qcloud", "myqcloud", "qq.com",
  "baidu", "bdstatic", "jd.com", "jdcloud", "bytedance", "volcengine",
  "huawei", "huaweicloud", "oraclecloud", "linode", "vultr", "digitalocean",
  "cloudapp", "compute.internal", "ec2.internal"
];

const FETCH_HEADERS = {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Accept": "application/json"
};

function ipToInt(ip) {
  return ip.split(".").reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
}

function intToIp(int) {
  return [(int >>> 24) & 255, (int >>> 16) & 255, (int >>> 8) & 255, int & 255].join(".");
}

function getCidrBlock(ipInt, bits) {
  const mask = ~(2 ** (32 - bits) - 1) >>> 0;
  return `${intToIp((ipInt & mask) >>> 0)}/${bits}`;
}

function isIpInCfCidr(ip) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
  const target = ipToInt(ip);
  return CF_CIDRS.some((cidr) => {
    const [range, bits] = cidr.split("/");
    const mask = ~(2 ** (32 - parseInt(bits, 10)) - 1) >>> 0;
    return (target & mask) === (ipToInt(range) & mask);
  });
}

function isPrivateOrReservedIp(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => isNaN(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  if (a === 10 || a === 127 || a === 0 || a >= 224) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function isBlacklistedName(domain) {
  const d = domain.toLowerCase().trim().replace(/\.$/, "");
  if (!d || d.startsWith("*") || !d.includes(".")) return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(d)) return true;
  if (BIG_TECH_KEYWORDS.some((kw) => d.includes(kw))) return true;
  if (/(\d{1,3}[-_.]){3}\d{1,3}/.test(d)) return true;
  return false;
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*"
    }
  });
}

async function fetchWithTimeout(url, options = {}, ms = 5000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...options, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function queryUrlscanCidr(cidr, targetInt, candidateMap, debugLogs) {
  // 关键修复：CIDR 必须用双引号包裹 ip:"x.x.x.x/xx"，否则 / 会触发 Lucene 正则语法报错 400
  const query = `ip:"${cidr}"`;
  const url = `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(query)}&size=100`;
  try {
    const res = await fetchWithTimeout(url, { headers: FETCH_HEADERS }, 6000);
    if (!res.ok) {
      debugLogs.push(`Urlscan (${cidr}) 返回状态码 ${res.status}`);
      return;
    }
    const data = await res.json();
    const rows = data.results || [];
    debugLogs.push(`Urlscan 在 ${cidr} 网段检索到 ${rows.length} 条历史网页快照`);
    for (const r of rows) {
      const page = r.page || {};
      const d = (page.domain || "").trim().toLowerCase();
      const pip = (page.ip || "").trim();
      const srv = (page.server || "").toLowerCase();
      if (!d || isBlacklistedName(d)) continue;
      if (srv.includes("cloudflare")) continue;

      const dist = /^\d{1,3}(\.\d{1,3}){3}$/.test(pip)
        ? Math.abs(ipToInt(pip) - targetInt)
        : 1024;

      if (!candidateMap.has(d) || candidateMap.get(d).dist > dist) {
        candidateMap.set(d, { domain: d, sourceIp: pip || cidr.split("/")[0], dist });
      }
    }
  } catch (err) {
    debugLogs.push(`Urlscan (${cidr}) 请求超时或异常: ${err.message}`);
  }
}

// 阶段 1：挖掘相邻子网关联域名
async function handleDiscover(url) {
  const targetIp = (url.searchParams.get("ip") || "").trim();
  const scope = Math.min(4, Math.max(1, parseInt(url.searchParams.get("scope") || "2", 10)));

  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(targetIp) || isPrivateOrReservedIp(targetIp)) {
    return jsonResponse({ error: "请输入合法的公网 IPv4 地址" }, 400);
  }

  const parts = targetIp.split(".").map(Number);
  const targetInt = ipToInt(targetIp);
  const candidateMap = new Map();
  const debugLogs = [];

  const cidrBits = scope === 1 ? 24 : scope === 2 ? 23 : 22;
  const primaryCidr = getCidrBlock(targetInt, cidrBits);

  // 1. 先检索选定相邻网段（/24、/23 或 /22）
  await queryUrlscanCidr(primaryCidr, targetInt, candidateMap, debugLogs);

  // 2. 若相邻子网内被收录的公开站点不足 6 个，自动扩展至同机房分配块 (/20) 补充并按 IP 距离排序
  if (candidateMap.size < 6) {
    const parentCidr20 = getCidrBlock(targetInt, 20);
    if (parentCidr20 !== primaryCidr) {
      debugLogs.push(`相邻网段候选较少，自动扩展至同机房分配块 ${parentCidr20} 补充搜索...`);
      await queryUrlscanCidr(parentCidr20, targetInt, candidateMap, debugLogs);
    }
  }

  // 3. 补充查询最邻近 20 个 IP 的 Shodan InternetDB 记录
  const neighborIps = [];
  for (let offset = 1; offset <= 10; offset++) {
    if (parts[3] - offset >= 1) neighborIps.push(`${parts[0]}.${parts[1]}.${parts[2]}.${parts[3] - offset}`);
    if (parts[3] + offset <= 254) neighborIps.push(`${parts[0]}.${parts[1]}.${parts[2]}.${parts[3] + offset}`);
  }

  let shodanHits = 0;
  await Promise.all(
    neighborIps.map(async (nip) => {
      const dist = Math.abs(ipToInt(nip) - targetInt);
      try {
        const res = await fetchWithTimeout(`https://internetdb.shodan.io/${nip}`, { headers: FETCH_HEADERS }, 3500);
        if (!res.ok) return;
        const data = await res.json();
        const ports = data.ports || [];
        const hosts = data.hostnames || [];
        if (ports.includes(443) && hosts.length > 0) {
          for (const h of hosts) {
            const d = h.trim().toLowerCase();
            if (!isBlacklistedName(d) && !candidateMap.has(d)) {
              shodanHits++;
              candidateMap.set(d, { domain: d, sourceIp: nip, dist });
            }
          }
        }
      } catch {}
    })
  );
  debugLogs.push(`Shodan InternetDB 从邻近 IP 443 端口提取到 ${shodanHits} 个主机名`);

  const candidates = Array.from(candidateMap.values())
    .sort((a, b) => a.dist - b.dist)
    .slice(0, 50);

  return jsonResponse({
    cidr: primaryCidr,
    debugLogs,
    candidates
  });
}

// 阶段 2：分批验证候选域名（真实 HTTPS 握手 + 多维 Cloudflare 深度过滤）
async function handleVerify(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "无效的请求体" }, 400);
  }

  const items = Array.isArray(body.items) ? body.items.slice(0, 10) : [];
  const targetPrefix = (body.prefix || "").trim();
  const verified = [];
  const blocked = [];

  await Promise.all(
    items.map(async (item) => {
      const domain = (item.domain || "").toLowerCase().trim();
      if (!domain || isBlacklistedName(domain)) return;

      let resolvedIps = [];
      let cnames = [];
      try {
        const dnsRes = await fetchWithTimeout(
          `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=1`,
          { headers: { Accept: "application/dns-json" } },
          3000
        );
        if (dnsRes.ok) {
          const dnsData = await dnsRes.json();
          for (const ans of dnsData.Answer || []) {
            if (ans.type === 1) resolvedIps.push(ans.data);
            if (ans.type === 5) cnames.push(ans.data.toLowerCase());
          }
        }
      } catch {
        return;
      }

      if (resolvedIps.length === 0) return;

      for (const cn of cnames) {
        if (cn.includes("cloudflare") || isBlacklistedName(cn)) {
          blocked.push({ domain, reason: `CNAME 命中黑名单 (${cn})` });
          return;
        }
      }

      const cfIp = resolvedIps.find((ip) => isIpInCfCidr(ip));
      if (cfIp) {
        blocked.push({ domain, reason: `解析 IP 命中 Cloudflare CIDR (${cfIp})` });
        return;
      }

      try {
        const headRes = await fetchWithTimeout(
          `https://${domain}/`,
          {
            method: "HEAD",
            redirect: "manual",
            headers: { "User-Agent": FETCH_HEADERS["User-Agent"] }
          },
          3500
        );

        const serverHdr = (headRes.headers.get("server") || "").toLowerCase();
        const hasCfRay = headRes.headers.has("cf-ray") || headRes.headers.has("cf-cache-status");

        if (serverHdr.includes("cloudflare") || hasCfRay) {
          blocked.push({ domain, reason: "HTTPS 响应头命中 Cloudflare 特征 (CF-RAY/Server)" });
          return;
        }

        const primaryIp = resolvedIps[0];
        const sameBlock = targetPrefix && primaryIp.startsWith(targetPrefix);

        verified.push({
          domain,
          ip: primaryIp,
          sourceIp: item.sourceIp,
          dist: sameBlock ? item.dist : item.dist + 500,
          sameBlock
        });
      } catch {}
    })
  );

  return jsonResponse({ verified, blocked });
}

export async function onRequest(context) {
  const { request } = context;
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type"
      }
    });
  }

  const url = new URL(request.url);
  if (url.pathname === "/api/discover" && request.method === "GET") {
    return handleDiscover(url);
  }
  if (url.pathname === "/api/verify" && request.method === "POST") {
    return handleVerify(request);
  }

  return jsonResponse({ error: "Not Found" }, 404);
}