// Issue #563 — run-side self-approval guard on the UI admin approval path.
//
// `approveReviewTask` (the operator's Continue/Approve server action) is the
// run-side analog of the agent-creation decide self-approval guard. It blocks an
// admin from rubber-stamping their OWN run's pending_approval HITL gate when
// ANOTHER platform_admin exists who could review it (separation of duties),
// while permitting the SOLE admin to clear their own run (the single-admin
// exception that #382/#392 / PR #557 established on the agent-creation side).
//
// This pins:
//   - other admins exist + actor is the run initiator -> BLOCK (throws, no resume);
//   - NO other admin (sole admin) + actor is the run initiator -> ALLOW (resume);
//   - actor is NOT the run initiator (a different admin reviewing) -> ALLOW even
//     with other admins (this is the SoD-honoring path, not self-approval);
//   - connector_config.agent_run.allowSelfApproval=true -> ALLOW even with other
//     admins (global escape hatch);
//   - wayflow- prefix resolves the run via readAgentRunByTaskId for the same guard.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/auth-session", () => ({
  requireAuthSession: vi.fn(async () => ({
    user: { id: "admin-1", email: "operator@example.com" },
    session: { activeOrganizationId: "org-1" },
  })),
  requireAdminSession: vi.fn(async () => ({
    user: { id: "admin-1", email: "operator@example.com" },
  })),
  buildCanDoOptsFromSession: vi.fn(() => ({})),
  isPlatformAdmin: vi.fn(() => true),
}));

vi.mock("@/lib/authz", () => ({
  canDo: vi.fn(async () => ({ ok: true })),
  AuthzError: class AuthzError extends Error {},
  logAuditEvent: vi.fn(async () => {}),
}));

vi.mock("@/lib/agent-url", () => ({
  buildAgentWorkspacePath: vi.fn(() => "/agents/foo"),
}));

vi.mock("@/lib/background-jobs", () => ({
  enqueueBackgroundJob: vi.fn(async () => {}),
  BACKGROUND_JOB_NAMES: {} as Record<string, string>,
}));

vi.mock("@/lib/primitive-handlers", () => ({
  collectAllPrimitiveHandlers: vi.fn(() => []),
}));

// Guard dependencies — the two knobs the #563 guard reads.
const { countOtherPlatformAdminsMock } = vi.hoisted(() => ({
  countOtherPlatformAdminsMock: vi.fn(async () => 0),
}));
vi.mock("@/lib/better-auth-db", () => ({
  countOtherPlatformAdmins: countOtherPlatformAdminsMock,
  readTeamForOrg: vi.fn(async () => null),
}));

const { readConnectorConfigMock } = vi.hoisted(() => ({
  // Default: allowSelfApproval not set -> guard ON.
  readConnectorConfigMock: vi.fn(() => ({})),
}));
vi.mock("@/lib/database", () => ({
  readConnectorConfigFromDatabase: readConnectorConfigMock,
}));

// Run resolution — controls run.runBy for both synthetic prefixes.
const { readAgentRunByIdMock, readAgentRunByTaskIdMock } = vi.hoisted(() => ({
  readAgentRunByIdMock: vi.fn(),
  readAgentRunByTaskIdMock: vi.fn(),
}));
vi.mock("../store", () => ({
  readAgentRunById: readAgentRunByIdMock,
  readAgentRunByTaskId: readAgentRunByTaskIdMock,
  // Remaining store exports are referenced at module load but unused here.
  createAuditEvent: vi.fn(),
  deleteAgentTemplate: vi.fn(),
  readAgentTemplateById: vi.fn(),
  readAgentTemplateByPackageName: vi.fn(),
  readAgentVersionsByTemplate: vi.fn(),
  readAgentVersionById: vi.fn(),
  createAgentTemplate: vi.fn(),
  createAgentVersion: vi.fn(),
  createAgentRun: vi.fn(),
  createShareBinding: vi.fn(),
  createAgentFork: vi.fn(),
  checkRegistryPermission: vi.fn(),
  readRegistryEntryById: vi.fn(),
  updateAgentTemplate: vi.fn(),
  updateShareBinding: vi.fn(),
  createAgentTemplateVersionIfChanged: vi.fn(),
  rollbackAgentTemplateToVersion: vi.fn(),
  updateAgentTemplateOrigin: vi.fn(),
}));

vi.mock("../compiler", () => ({
  compileWorkflow: vi.fn(),
}));

vi.mock("../verdaccio/publish-metadata", () => ({
  derivePublishMetadataFromSnapshot: vi.fn(() => ({
    riskLevel: "low",
    toolAccess: [],
    hasApprovalGates: false,
  })),
}));

vi.mock("@cinatra-ai/registries", async () => {
  const actual = await vi.importActual<typeof import("@cinatra-ai/registries")>("@cinatra-ai/registries");
  return { ...actual };
});

vi.mock("../verdaccio/client", () => ({
  publishAgentPackage: vi.fn(async () => {}),
}));

vi.mock("../install-from-package", () => ({
  installAgentFromPackage: vi.fn(async () => {}),
  installAgentPackageWithDependencies: vi.fn(async () => {}),
}));

vi.mock("next/navigation", () => ({
  redirect: vi.fn(),
}));

vi.mock("next/cache", () => ({
  revalidatePath: vi.fn(),
}));

const { approveReviewTaskInternalMock } = vi.hoisted(() => ({
  approveReviewTaskInternalMock: vi.fn(async () => {}),
}));
vi.mock("../review-task-actions", () => ({
  approveReviewTaskInternal: approveReviewTaskInternalMock,
}));

import { approveReviewTask } from "../actions";

beforeEach(() => {
  vi.clearAllMocks();
  // Re-establish defaults cleared by clearAllMocks.
  countOtherPlatformAdminsMock.mockResolvedValue(0);
  readConnectorConfigMock.mockReturnValue({});
  approveReviewTaskInternalMock.mockResolvedValue(undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("approveReviewTask — run-side self-approval guard (#563)", () => {
  it("BLOCKS self-approval when another platform_admin exists (SoD preserved)", async () => {
    // run initiated by the approving admin
    readAgentRunByIdMock.mockResolvedValue({ id: "run-1", runBy: "admin-1" });
    countOtherPlatformAdminsMock.mockResolvedValue(1); // a second admin could review

    await expect(approveReviewTask("setup-run-1")).rejects.toThrow(/self-approval is disallowed/);

    // No resume happened.
    expect(approveReviewTaskInternalMock).not.toHaveBeenCalled();
    expect(countOtherPlatformAdminsMock).toHaveBeenCalledWith("admin-1");
  });

  it("ALLOWS the SOLE admin to approve their own run (single-admin unblock)", async () => {
    readAgentRunByIdMock.mockResolvedValue({ id: "run-1", runBy: "admin-1" });
    countOtherPlatformAdminsMock.mockResolvedValue(0); // no other admin -> no deadlock

    await expect(approveReviewTask("setup-run-1", { url: "x" }, "url")).resolves.toBeUndefined();

    expect(approveReviewTaskInternalMock).toHaveBeenCalledTimes(1);
    expect(approveReviewTaskInternalMock).toHaveBeenCalledWith(
      "setup-run-1",
      "admin-1",
      { url: "x" },
      "url",
      undefined,
    );
  });

  it("ALLOWS a DIFFERENT admin to approve a run they did not initiate (not self-approval)", async () => {
    // run initiated by someone else; the guard's self-check does not fire,
    // so the admin-count is never consulted and the resume proceeds.
    readAgentRunByIdMock.mockResolvedValue({ id: "run-1", runBy: "other-user" });
    countOtherPlatformAdminsMock.mockResolvedValue(5);

    await expect(approveReviewTask("setup-run-1")).resolves.toBeUndefined();

    expect(approveReviewTaskInternalMock).toHaveBeenCalledTimes(1);
    expect(countOtherPlatformAdminsMock).not.toHaveBeenCalled();
  });

  it("ALLOWS self-approval with other admins when connector_config.agent_run.allowSelfApproval=true", async () => {
    readAgentRunByIdMock.mockResolvedValue({ id: "run-1", runBy: "admin-1" });
    countOtherPlatformAdminsMock.mockResolvedValue(3);
    readConnectorConfigMock.mockReturnValue({ allowSelfApproval: true });

    await expect(approveReviewTask("setup-run-1")).resolves.toBeUndefined();

    expect(approveReviewTaskInternalMock).toHaveBeenCalledTimes(1);
    // Override short-circuits before any admin-count read.
    expect(countOtherPlatformAdminsMock).not.toHaveBeenCalled();
  });

  it("resolves the run via task id for the wayflow- prefix and blocks self-approval", async () => {
    readAgentRunByTaskIdMock.mockResolvedValue({ id: "run-w", runBy: "admin-1" });
    countOtherPlatformAdminsMock.mockResolvedValue(2);

    await expect(approveReviewTask("wayflow-task-9")).rejects.toThrow(/self-approval is disallowed/);

    expect(readAgentRunByTaskIdMock).toHaveBeenCalledWith("task-9");
    expect(approveReviewTaskInternalMock).not.toHaveBeenCalled();
  });

  it("falls through (no guard) when the run cannot be resolved — downstream helper owns the not-found error", async () => {
    readAgentRunByIdMock.mockResolvedValue(null);
    countOtherPlatformAdminsMock.mockResolvedValue(9);

    await expect(approveReviewTask("setup-missing")).resolves.toBeUndefined();

    // Guard cannot bind to an absent run -> never consults the admin count,
    // and hands off to the internal helper (which raises the canonical error).
    expect(countOtherPlatformAdminsMock).not.toHaveBeenCalled();
    expect(approveReviewTaskInternalMock).toHaveBeenCalledTimes(1);
  });
});
