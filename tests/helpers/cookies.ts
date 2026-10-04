/** A minimal cookie jar for driving auth flows through the Worker. */
export interface ParsedCookie {
  name: string;
  value: string;
  attributes: Record<string, string | true>;
}

export function parseSetCookie(header: string): ParsedCookie {
  const [pair = "", ...attrs] = header.split(";").map((part) => part.trim());
  const index = pair.indexOf("=");
  const attributes: Record<string, string | true> = {};
  for (const attr of attrs) {
    const [key = "", ...rest] = attr.split("=");
    attributes[key.toLowerCase()] = rest.length > 0 ? rest.join("=") : true;
  }
  return { name: pair.slice(0, index), value: pair.slice(index + 1), attributes };
}

export class CookieJar {
  private readonly cookies = new Map<string, string>();

  store(response: Response): ParsedCookie[] {
    const parsed = response.headers.getSetCookie().map(parseSetCookie);
    for (const cookie of parsed) {
      const expired = cookie.value === "" || cookie.attributes["max-age"] === "0";
      if (expired) this.cookies.delete(cookie.name);
      else this.cookies.set(cookie.name, cookie.value);
    }
    return parsed;
  }

  header(): string {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  }

  get(name: string): string | undefined {
    return this.cookies.get(name);
  }

  set(name: string, value: string): void {
    this.cookies.set(name, value);
  }

  names(): string[] {
    return [...this.cookies.keys()];
  }
}
