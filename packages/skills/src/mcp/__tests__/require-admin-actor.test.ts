/**
 * `requireAdminActor` must allow the trusted platform-admin hint to
 * early-exit.
 *
 * `actorContextFromMcpRequest` derives `platformRole` exclusively from
 * `getAuthSession()` and drops `actor.platformRole`. Without the early-
 * exit, the localhost dev bypass (which stamps `platform_admin` on the
 * actor envelope) never reaches the gate.
 */
import { describe, it, expect, vi } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("@/lib/auth-session", () => ({
  getAuthSession: vi.fn(async () => null),
  isPlatformAdmin: vi.fn(() => false),
}));
vi.mock("@cinatra-ai/agents/auth-policy", () => ({
  actorContextFromMcpRequest: vi.fn(async () => ({ platformRole: undefined })),
}));

import { requireAdminActor } from "../auth";

describe("requireAdminActor trusted-hint early-exit", () => {
  it("returns immediately when actor.platformRole='platform_admin'", async () => {
    await expect(
      requireAdminActor({ platformRole: "platform_admin" } as never),
    ).resolves.toBeUndefined();
  });

  it("rejects when no platformRole hint AND no session admin", async () => {
    await expect(
      requireAdminActor({} as never),
    ).rejects.toMatchObject({ code: "not_admin" });
  });

  it("rejects when actor.platformRole='member'", async () => {
    await expect(
      requireAdminActor({ platformRole: "member" } as never),
    ).rejects.toMatchObject({ code: "not_admin" });
  });
});
