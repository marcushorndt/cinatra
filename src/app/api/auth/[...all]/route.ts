import { toNextJsHandler } from "better-auth/next-js";
import { auth } from "@/lib/auth";

const authHandlers = toNextJsHandler(auth);

// The Cinatra MCP resource requires the `mcp:connect` scope to authorize
// (see `requiredScopes` in packages/mcp-server/src/index.tsx). Some MCP
// clients — notably the MCP CLI proxy — perform Dynamic Client Registration
// with a narrow scope set (e.g. `openid email profile`) and only request
// `mcp:connect` at authorize time, discovered from the protected-resource
// metadata. Better Auth's `clientRegistrationDefaultScopes` only fills scopes
// when the client OMITS `scope`, so an explicit narrow scope bypasses the
// default and the subsequent authorize fails with `invalid_scope` →
// "No authorization code received".
//
// To make those clients connect out of the box, union `mcp:connect` into any
// DCR request that already carries an explicit scope. Requests that omit
// `scope` are left untouched so Better Auth still applies its full default
// scope set (which already includes `mcp:connect`).
const REQUIRED_MCP_SCOPE = "mcp:connect";

function isDynamicClientRegistration(request: Request): boolean {
  if (request.method !== "POST") return false;
  try {
    return new URL(request.url).pathname.endsWith("/oauth2/register");
  } catch {
    return false;
  }
}

async function ensureRequiredScopeOnRegistration(request: Request): Promise<Request> {
  let body: unknown;
  try {
    body = await request.clone().json();
  } catch {
    return request; // not JSON — pass through untouched
  }

  if (typeof body !== "object" || body === null) return request;

  const record = body as Record<string, unknown>;
  const existing = typeof record.scope === "string" ? record.scope.trim() : "";

  // Omitted scope → let Better Auth apply clientRegistrationDefaultScopes.
  if (existing === "") return request;

  const scopes = new Set(existing.split(/\s+/).filter(Boolean));
  if (scopes.has(REQUIRED_MCP_SCOPE)) return request;

  scopes.add(REQUIRED_MCP_SCOPE);
  const nextBody = JSON.stringify({ ...record, scope: [...scopes].join(" ") });

  const headers = new Headers(request.headers);
  headers.delete("content-length");
  return new Request(request.url, {
    method: request.method,
    headers,
    body: nextBody,
  });
}

export async function GET(
  ...args: Parameters<typeof authHandlers.GET>
): ReturnType<typeof authHandlers.GET> {
  return authHandlers.GET(...args);
}

export async function POST(
  ...args: Parameters<typeof authHandlers.POST>
): ReturnType<typeof authHandlers.POST> {
  const [request] = args;
  if (request instanceof Request && isDynamicClientRegistration(request)) {
    const patched = await ensureRequiredScopeOnRegistration(request);
    return authHandlers.POST(patched);
  }
  return authHandlers.POST(...args);
}
