// Cloudflare 官方 IPv4 CIDR 网段
const CF_CIDRS = [
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
  "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
  "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
  "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
];

// 大陆有 CDN 节点的大厂及云默认域名关键字黑名单
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

function ipToInt(ip) {
  return ip.split(".").reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
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

async function fetchWithTimeout(url, options = {}, ms = 3000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...options, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// 阶段 1：挖掘相邻子网关联域名（严格控制在 25 次子请求以内）
async function handleDiscover(url) {
  const targetIp = (url.searchParams.get("ip") || "").trim();
  const scope = Math.min(2, Math.max(1, parseInt(url.searchParams.get("scope") || "2", 10)));

  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(targetIp) || isPrivateOrReservedIp(targetIp)) {
    return jsonResponse({ error: "请输入合法的公网 IPv4 地址" }, 400);
  }

  const parts = targetIp.split(".").map(Number);
  const subnets = [parts[2]];
  if (scope >= 2) {
    subnets.push(parts[2] > 0 ? parts[2] - 1 : parts[2] + 1);
  }

  const candidateMap = new Map(); // domain -> { domain, sourceIp, dist }
  const tasks = [];

  // 1. 整段 /24 反向 IP 批量检索（每个 /24 仅消耗 1 个子请求）
  for (const sub of subnets) {
    const cidr = `${parts[0]}.${parts[1]}.${sub}.0/24`;
    tasks.push(
      fetchWithTimeout(`https://api.hackertarget.com/reverseiplookup/?q=${cidr}`, {}, 4000)
        .then(async (res) => {
          if (!res.ok) return;
          const text = await res.text();
          if (text.includes("error") || text.includes("API count exceeded")) return;
          for (const line of text.split("\n")) {
            const d = line.trim().toLowerCase();
            if (d && !isBlacklistedName(d) && !candidateMap.has(d)) {
              const dist = Math.abs(sub - parts[2]) * 256 + 64;
              candidateMap.set(d, { domain: d, sourceIp: `${parts[0]}.${parts[1]}.${sub}.x`, dist });
            }
          }
        })
        .catch(() => {})
    );
  }

  // 2. 针对目标 IP 及最邻近的 8 个邻居 IP 查询 Passive DNS（解决无 PTR 问题）
  const neighborIps = [targetIp];
  for (let offset = 1; offset <= 4; offset++) {
    if (parts[3] - offset >= 1) neighborIps.push(`${parts[0]}.${parts[1]}.${parts[2]}.${parts[3] - offset}`);
    if (parts[3] + offset <= 254) neighborIps.push(`${parts[0]}.${parts[1]}.${parts[2]}.${parts[3] + offset}`);
  }

  for (const nip of neighborIps.slice(0, 8)) {
    const nParts = nip.split(".").map(Number);
    const dist = Math.abs(nParts[2] - parts[2]) * 256 + Math.abs(nParts[3] - parts[3]);
    tasks.push(
      fetchWithTimeout(`https://otx.alienvault.com/api/v1/indicators/IPv4/${nip}/passive_dns`, {}, 3500)
        .then(async (res) => {
          if (!res.ok) return;
          const data = await res.json();
          for (const rec of data.passive_dns || []) {
            const d = (rec.hostname || "").trim().toLowerCase();
            if (d && !isBlacklistedName(d) && !candidateMap.has(d)) {
              candidateMap.set(d, { domain: d, sourceIp: nip, dist });
            }
          }
        })
        .catch(() => {})
    );
  }

  // 3. 并发查询最邻近 12 个 IP 的 DoH PTR 记录
  for (const nip of neighborIps.slice(0, 12)) {
    const rev = nip.split(".").reverse().join(".") + ".in-addr.arpa";
    const nParts = nip.split(".").map(Number);
    const dist = Math.abs(nParts[2] - parts[2]) * 256 + Math.abs(nParts[3] - parts[3]);
    tasks.push(
      fetchWithTimeout(`https://cloudflare-dns.com/dns-query?name=${rev}&type=12`, {
        headers: { Accept: "application/dns-json" }
      }, 2500)
        .then(async (res) => {
          if (!res.ok) return;
          const data = await res.json();
          for (const ans of data.Answer || []) {
            if (ans.type === 12 && ans.data) {
              const d = ans.data.replace(/\.$/, "").toLowerCase();
              if (!isBlacklistedName(d) && !candidateMap.has(d)) {
                candidateMap.set(d, { domain: d, sourceIp: nip, dist });
              }
            }
          }
        })
        .catch(() => {})
    );
  }

  await Promise.all(tasks);

  const candidates = Array.from(candidateMap.values())
    .sort((a, b) => a.dist - b.dist)
    .slice(0, 60);

  return jsonResponse({
    subnets: subnets.map((s) => `${parts[0]}.${parts[1]}.${s}.0/24`),
    candidates
  });
}

// 阶段 2：分批验证候选域名（每批最多 12 个域名，约 24 个子请求，安全不超限）
async function handleVerify(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "无效的请求体" }, 400);
  }

  const items = Array.isArray(body.items) ? body.items.slice(0, 12) : [];
  const targetPrefix = (body.prefix || "").trim(); // 例如 "20.249."
  const verified = [];
  const blocked = [];

  await Promise.all(
    items.map(async (item) => {
      const domain = (item.domain || "").toLowerCase().trim();
      if (!domain || isBlacklistedName(domain)) return;

      // 1. DoH 查询 A 记录与 CNAME 链
      let resolvedIps = [];
      let cnames = [];
      try {
        const dnsRes = await fetchWithTimeout(
          `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=1`,
          { headers: { Accept: "application/dns-json" } },
          2500
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

      // 检查 CNAME 是否指向 Cloudflare 或大厂
      for (const cn of cnames) {
        if (cn.includes("cloudflare") || isBlacklistedName(cn)) {
          blocked.push({ domain, reason: `CNAME 命中黑名单 (${cn})` });
          return;
        }
      }

      // 检查是否命中 Cloudflare IPv4 CIDR
      const cfIp = resolvedIps.find((ip) => isIpInCfCidr(ip));
      if (cfIp) {
        blocked.push({ domain, reason: `解析 IP 命中 Cloudflare CIDR (${cfIp})` });
        return;
      }

      // 2. 发起真实 HTTPS HEAD 请求，检查 TLS 连通性与 Cloudflare 特征响应头 (CF-RAY / Server)
      try {
        const headRes = await fetchWithTimeout(
          `https://${domain}/`,
          {
            method: "HEAD",
            redirect: "manual",
            headers: { "User-Agent": "Mozilla/5.0" }
          },
          3000
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
      } catch {
        // HTTPS 握手失败或超时，直接淘汰
      }
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