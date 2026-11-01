/**
 * Trust Layer — SSRF Guard v1.0
 * Pre-connection DNS validation to block Server-Side Request Forgery attacks.
 * Checks every resolved IP against all blocked ranges before any connection is made.
 */

import dns from 'node:dns/promises';

/**
 * Parse an IPv4 address into a 32-bit unsigned integer.
 * @param {string} ip
 * @returns {number|null}
 */
function ipv4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let val = 0;
  for (const part of parts) {
    const n = parseInt(part, 10);
    if (isNaN(n) || n < 0 || n > 255) return null;
    val = (val << 8) + n;
  }
  return val >>> 0; // unsigned 32-bit
}

/**
 * Check if an IPv4 address falls within a CIDR block.
 * @param {string} ip
 * @param {string} cidr  e.g. "10.0.0.0/8"
 * @returns {boolean}
 */
function isInCIDR(ip, cidr) {
  const [range, bits] = cidr.split('/');
  const mask = bits === undefined ? 32 : parseInt(bits, 10);
  const ipInt = ipv4ToInt(ip);
  const rangeInt = ipv4ToInt(range);
  if (ipInt === null || rangeInt === null) return false;
  if (mask === 0) return true;
  const shift = 32 - mask;
  return (ipInt >>> shift) === (rangeInt >>> shift);
}

/**
 * Check if an IPv6 address is in a given prefix (simple prefix-matching for our known ranges).
 * Supports exact match and prefix match (e.g. fe80::, fc00::, ff00::, ::ffff:)
 * @param {string} ip  - already lowercased
 * @param {string} prefix
 * @param {number} prefixBits
 * @returns {boolean}
 */
function isIPv6InRange(ip, prefix, prefixBits) {
  // Expand both to full 128-bit arrays (16 bytes)
  function expand(addr) {
    // handle ::ffff:x.x.x.x  IPv4-mapped
    if (addr.startsWith('::ffff:') && addr.split(':').length < 8) {
      const v4part = addr.slice(7);
      const v4parts = v4part.split('.');
      if (v4parts.length === 4) {
        const bytes = new Uint8Array(16);
        bytes[10] = 0xff;
        bytes[11] = 0xff;
        v4parts.forEach((p, i) => { bytes[12 + i] = parseInt(p, 10); });
        return bytes;
      }
    }

    const parts = addr.split('::');
    let left = parts[0] ? parts[0].split(':') : [];
    let right = parts[1] ? parts[1].split(':') : [];

    // IPv4-mapped embedded in right part
    const last = right[right.length - 1] || '';
    if (last.includes('.')) {
      const v4parts = last.split('.');
      const hi = ((parseInt(v4parts[0], 10) << 8) | parseInt(v4parts[1], 10)).toString(16).padStart(4, '0');
      const lo = ((parseInt(v4parts[2], 10) << 8) | parseInt(v4parts[3], 10)).toString(16).padStart(4, '0');
      right = right.slice(0, -1).concat([hi, lo]);
    }

    const missing = 8 - left.length - right.length;
    const groups = [...left, ...Array(missing).fill('0'), ...right];
    const bytes = new Uint8Array(16);
    groups.forEach((g, i) => {
      const val = parseInt(g || '0', 16);
      bytes[i * 2] = (val >> 8) & 0xff;
      bytes[i * 2 + 1] = val & 0xff;
    });
    return bytes;
  }

  try {
    const ipBytes = expand(ip);
    const pfxBytes = expand(prefix);
    const fullBytes = Math.floor(prefixBits / 8);
    const remBits = prefixBits % 8;
    for (let i = 0; i < fullBytes; i++) {
      if (ipBytes[i] !== pfxBytes[i]) return false;
    }
    if (remBits > 0) {
      const mask = (0xff << (8 - remBits)) & 0xff;
      if ((ipBytes[fullBytes] & mask) !== (pfxBytes[fullBytes] & mask)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Detect IPv4-mapped IPv6 addresses like ::ffff:10.0.0.1 and return the inner IPv4.
 * @param {string} ip
 * @returns {string|null}
 */
function extractIPv4FromMapped(ip) {
  const lower = ip.toLowerCase();
  // ::ffff:d.d.d.d
  const mapped = lower.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (mapped) return mapped[1];
  // ::ffff:hhhh:hhhh
  const hexMapped = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hexMapped) {
    const hi = parseInt(hexMapped[1], 16);
    const lo = parseInt(hexMapped[2], 16);
    return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
  }
  return null;
}

/**
 * Check whether a single IP address (v4 or v6) is blocked.
 * @param {string} ip
 * @returns {{ blocked: boolean, reason: string|null }}
 */
function checkIpBlocked(ip) {
  const lower = ip.toLowerCase().trim().replace(/^\[|\]$/g, '');

  // IPv4-mapped IPv6 — extract and check the inner v4 address
  const innerV4 = extractIPv4FromMapped(lower);
  if (innerV4) {
    const innerCheck = checkIpBlocked(innerV4);
    if (innerCheck.blocked) {
      return { blocked: true, reason: `IPv4-mapped IPv6 address resolves to blocked range: ${innerV4} (${innerCheck.reason})` };
    }
    return { blocked: false, reason: null };
  }

  // ── IPv4 Checks ──
  if (/^\d+\.\d+\.\d+\.\d+$/.test(lower)) {
    if (isInCIDR(lower, '0.0.0.0/8')) return { blocked: true, reason: 'Current-network / unspecified range (0.0.0.0/8)' };
    if (isInCIDR(lower, '127.0.0.0/8')) return { blocked: true, reason: 'Loopback address (127.0.0.0/8)' };
    if (isInCIDR(lower, '10.0.0.0/8')) return { blocked: true, reason: 'Private network (10.0.0.0/8)' };
    if (isInCIDR(lower, '172.16.0.0/12')) return { blocked: true, reason: 'Private network (172.16.0.0/12)' };
    if (isInCIDR(lower, '192.168.0.0/16')) return { blocked: true, reason: 'Private network (192.168.0.0/16)' };
    if (isInCIDR(lower, '169.254.0.0/16')) return { blocked: true, reason: 'Link-local / Cloud metadata (169.254.0.0/16)' };
    if (isInCIDR(lower, '100.64.0.0/10')) return { blocked: true, reason: 'Shared address space / CGNAT (100.64.0.0/10)' };
    if (isInCIDR(lower, '192.0.0.0/24')) return { blocked: true, reason: 'IETF protocol-assignment range (192.0.0.0/24)' };
    if (isInCIDR(lower, '192.0.2.0/24')) return { blocked: true, reason: 'Documentation range (192.0.2.0/24)' };
    if (isInCIDR(lower, '192.88.99.0/24')) return { blocked: true, reason: 'Deprecated 6to4 relay range (192.88.99.0/24)' };
    if (isInCIDR(lower, '198.18.0.0/15')) return { blocked: true, reason: 'Benchmarking range (198.18.0.0/15)' };
    if (isInCIDR(lower, '198.51.100.0/24')) return { blocked: true, reason: 'Documentation range (198.51.100.0/24)' };
    if (isInCIDR(lower, '203.0.113.0/24')) return { blocked: true, reason: 'Documentation range (203.0.113.0/24)' };
    if (isInCIDR(lower, '224.0.0.0/4')) return { blocked: true, reason: 'Multicast address (224.0.0.0/4)' };
    if (isInCIDR(lower, '240.0.0.0/4')) return { blocked: true, reason: 'Reserved address range (240.0.0.0/4)' };
    return { blocked: false, reason: null };
  }

  // ── IPv6 Checks ──
  if (lower === '::' || lower === '0:0:0:0:0:0:0:0') {
    return { blocked: true, reason: 'Unspecified IPv6 address (::)' };
  }
  if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') {
    return { blocked: true, reason: 'Loopback IPv6 address (::1)' };
  }
  // Link-local fe80::/10
  if (isIPv6InRange(lower, 'fe80::', 10)) {
    return { blocked: true, reason: 'Link-local IPv6 (fe80::/10)' };
  }
  // Unique-local fc00::/7 (includes fd00::/8)
  if (isIPv6InRange(lower, 'fc00::', 7)) {
    return { blocked: true, reason: 'Unique-local IPv6 (fc00::/7)' };
  }
  // Multicast ff00::/8
  if (isIPv6InRange(lower, 'ff00::', 8)) {
    return { blocked: true, reason: 'Multicast IPv6 (ff00::/8)' };
  }
  // Permit only global-unicast space, then exclude special-purpose prefixes
  // that are not generally suitable as public investigation destinations.
  if (!isIPv6InRange(lower, '2000::', 3)) {
    return { blocked: true, reason: 'IPv6 address is outside global-unicast space (2000::/3)' };
  }
  for (const [prefix, bits, reason] of [
    ['2001::', 23, 'IETF protocol-assignment range (2001::/23)'],
    ['2001:2::', 48, 'Benchmarking range (2001:2::/48)'],
    ['2001:db8::', 32, 'Documentation range (2001:db8::/32)'],
    ['2002::', 16, '6to4 transition range (2002::/16)'],
    ['3fff::', 20, 'Documentation range (3fff::/20)'],
    ['5f00::', 16, 'Segment-routing range (5f00::/16)']
  ]) {
    if (isIPv6InRange(lower, prefix, bits)) return { blocked: true, reason };
  }

  return { blocked: false, reason: null };
}

export class SSRFGuard {
  /**
   * Validate URL and resolve hostname IPs before connection.
   * @param {string} urlStr  — The URL string to validate
   * @param {{ skipDns?: boolean }} options
   * @returns {Promise<{ allowed: boolean, blockedReason: string|null, resolvedIps: string[], canonicalUrl: string }>}
   */
  static async validateAndResolve(urlStr, options = {}) {
    // -- TEST-ONLY BYPASS (never set in production code paths) --
    if (options._testBypassSsrf === true) {
      let cu = urlStr; try { cu = new URL(urlStr).href; } catch {}
      return { allowed: true, blockedReason: null, resolvedIps: [], canonicalUrl: cu, connectAddress: null };
    }
    let parsed;
    try {
      parsed = new URL(urlStr);
    } catch {
      return {
        allowed: false,
        blockedReason: `Malformed URL: cannot parse "${urlStr}"`,
        resolvedIps: [],
        canonicalUrl: urlStr
      };
    }

    // 1. Scheme check — only http/https allowed
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return {
        allowed: false,
        blockedReason: `Disallowed URL scheme "${parsed.protocol}" — only http: and https: are permitted`,
        resolvedIps: [],
        canonicalUrl: parsed.href
      };
    }

    // 2. Embedded credential check
    if (parsed.username || parsed.password) {
      return {
        allowed: false,
        blockedReason: 'Embedded credentials in URL are prohibited (SSRF / credential leakage risk)',
        resolvedIps: [],
        canonicalUrl: parsed.href
      };
    }

    const rawHostname = parsed.hostname;
    const hostname = rawHostname.replace(/^\[|\]$/g, '');
    const canonicalUrl = parsed.href;

    // 3. Bare IP address — check directly without DNS lookup
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname) || hostname.includes(':')) {
      const check = checkIpBlocked(hostname);
      if (check.blocked) {
        return {
          allowed: false,
          blockedReason: `Direct IP address in hostname blocked: ${check.reason}`,
          resolvedIps: [hostname],
          canonicalUrl,
          connectAddress: null
        };
      }
      return {
        allowed: true,
        blockedReason: null,
        resolvedIps: [hostname],
        canonicalUrl,
        connectAddress: hostname
      };
    }

    // 4. Hostname string heuristics (pre-DNS — fast path for obvious names)
    const hostLower = hostname.toLowerCase();
    if (hostLower === 'localhost') {
      return {
        allowed: false,
        blockedReason: 'Hostname "localhost" is blocked (loopback)',
        resolvedIps: [],
        canonicalUrl
      };
    }

    // 5. DNS resolution (skippable in tests)
    if (options.skipDns) {
      return {
        allowed: true,
        blockedReason: null,
        resolvedIps: [],
        canonicalUrl
      };
    }

    let resolvedIps = [];
    try {
      // Resolve both A (IPv4) and AAAA (IPv6)
      const [v4Results, v6Results] = await Promise.race([
        Promise.allSettled([dns.resolve4(hostname), dns.resolve6(hostname)]),
        new Promise((_, reject) => setTimeout(() => reject(new Error('system DNS timed out')), 1500))
      ]);

      if (v4Results.status === 'fulfilled') resolvedIps.push(...v4Results.value);
      if (v6Results.status === 'fulfilled') resolvedIps.push(...v6Results.value);

      if (resolvedIps.length === 0) {
        // Try generic lookup as fallback
        try {
          const addrs = await Promise.race([
            dns.lookup(hostname, { all: true }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('system lookup timed out')), 1500))
          ]);
          resolvedIps = addrs.map(a => a.address);
        } catch {
          throw new Error('System DNS lookup failed or timed out');
        }
      }
    } catch {
      // A slow operating-system resolver must not stall live inspection. Use
      // DNS-over-HTTPS as a bounded fallback, then validate all returned IPs.
      const queryType = async (type) => {
        const queryUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`;
        const response = await fetch(queryUrl, {
          headers: { Accept: 'application/dns-json' },
          signal: AbortSignal.timeout(2500)
        });
        if (!response.ok) return [];
        const payload = await response.json();
        return (payload.Answer || [])
          .filter(record => (type === 'A' && record.type === 1) || (type === 'AAAA' && record.type === 28))
          .map(record => record.data);
      };
      const dohAnswers = await Promise.allSettled([queryType('A'), queryType('AAAA')]);
      for (const answer of dohAnswers) {
        if (answer.status === 'fulfilled') resolvedIps.push(...answer.value);
      }
      if (resolvedIps.length === 0) {
        return {
          allowed: false,
          blockedReason: `DNS resolution error for hostname "${hostname}"`,
          resolvedIps: [],
          canonicalUrl
        };
      }
    }

    // 6. Check every resolved IP
    for (const ip of resolvedIps) {
      const check = checkIpBlocked(ip);
      if (check.blocked) {
        return {
          allowed: false,
          blockedReason: `Hostname "${hostname}" resolves to blocked IP ${ip}: ${check.reason}`,
          resolvedIps,
          canonicalUrl
        };
      }
    }

    return {
      allowed: true,
      blockedReason: null,
      resolvedIps,
      canonicalUrl,
      connectAddress: resolvedIps[0] || null
    };
  }
}
