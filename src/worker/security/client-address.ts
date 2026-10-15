/**
 * The client network address, as rate limits may key on it.
 *
 * Only CF-Connecting-IP is trusted: Cloudflare's edge sets it on every
 * request and overwrites any client-supplied value. X-Forwarded-For,
 * X-Real-IP, True-Client-IP and similar headers are client-controlled here
 * and are never read.
 *
 * A missing or malformed value yields null, never a shared placeholder:
 * callers decide (authoritative limits refuse the request).
 *
 * IPv6 clients are keyed on their /64. A single subscriber usually holds a
 * whole /64 (often more), so per-/128 keys would let one client rotate
 * addresses to get a fresh counter on every request.
 */

const MAX_HEADER_LENGTH = 64;

function parseIPv4(text: string): number[] | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!match) return null;
  const octets = match.slice(1).map(Number);
  return octets.every((o) => o <= 255) ? octets : null;
}

/** Eight 16-bit groups, or null. Accepts `::` compression and a trailing dotted IPv4. */
function parseIPv6(text: string): number[] | null {
  if (!/^[0-9a-f:.]+$/.test(text)) return null;
  let head = text;
  const tail: number[] = [];
  const lastColon = head.lastIndexOf(":");
  if (head.includes(".")) {
    const v4 = parseIPv4(head.slice(lastColon + 1));
    if (!v4 || lastColon < 0) return null;
    tail.push(((v4[0] ?? 0) << 8) | (v4[1] ?? 0), ((v4[2] ?? 0) << 8) | (v4[3] ?? 0));
    head = head.slice(0, lastColon + 1);
    // "::1.2.3.4" leaves "::"; "64:ff9b::1.2.3.4" leaves "64:ff9b::"; "a:b:c:d:e:f:1.2.3.4" leaves "a:…:f:".
    if (head.endsWith(":") && !head.endsWith("::")) head = head.slice(0, -1);
  }
  const halves = head.split("::");
  if (halves.length > 2) return null;
  const groups = (part: string): number[] | null => {
    if (part === "") return [];
    const out: number[] = [];
    for (const group of part.split(":")) {
      if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
      out.push(parseInt(group, 16));
    }
    return out;
  };
  const left = groups(halves[0] ?? "");
  const right = halves.length === 2 ? groups(halves[1] ?? "") : [];
  if (!left || !right) return null;
  const explicit = left.length + right.length + tail.length;
  if (halves.length === 2) {
    if (explicit > 7) return null;
    return [...left, ...new Array<number>(8 - explicit).fill(0), ...right, ...tail];
  }
  return explicit === 8 ? [...left, ...tail] : null;
}

/**
 * The rate-limit identity of the client: a canonical IPv4 address, or the
 * client's IPv6 /64 as `xxxx:xxxx:xxxx:xxxx::/64`. IPv4-mapped IPv6
 * (`::ffff:a.b.c.d`) is the IPv4 address. Null when the trusted header is
 * missing or is not an IP address.
 */
export function rateLimitAddress(request: Request): string | null {
  const raw = request.headers.get("cf-connecting-ip");
  if (raw === null || raw.length === 0 || raw.length > MAX_HEADER_LENGTH) return null;
  const text = raw.trim().toLowerCase();
  const v4 = parseIPv4(text);
  if (v4) return v4.join(".");
  const v6 = parseIPv6(text);
  if (!v6) return null;
  if (v6.slice(0, 5).every((g) => g === 0) && v6[5] === 0xffff) {
    const [hi = 0, lo = 0] = v6.slice(6);
    return [hi >> 8, hi & 0xff, lo >> 8, lo & 0xff].join(".");
  }
  return `${v6.slice(0, 4).map((g) => g.toString(16)).join(":")}::/64`;
}
