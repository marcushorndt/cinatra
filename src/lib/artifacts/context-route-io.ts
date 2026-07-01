import "server-only";

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { resolveAgentInstallDir } from "@cinatra-ai/agents/agent-install-path";
import {
  readAgentRunById,
  readAgentRunByContextId,
  readAgentTemplateById,
  type AgentRunRecord,
} from "@cinatra-ai/agents";
import {
  readAgentContextSlotsFromOas,
  type AgentContextSlot,
} from "@cinatra-ai/extensions/agent-context-slots-reader";
import { isAuthorizedBridgeRequest } from "@/lib/wayflow-bridge-auth";
import { verifyLangGraphBridgeToken } from "@/lib/a2a-auth";
import { resolveAgentRunMcpActor } from "@/lib/agent-run-actor-resolve";
import { buildActorContextFromPrimitive } from "@/lib/authz/build-actor-context";
import type { ActorContext } from "@/lib/authz/actor-context";
import { readTeamsForUser, readProjectGrantsForUser } from "@/lib/better-auth-db";
import { resolveContextSlot } from "./context-resolver";
import { getInstalledExtensionDescriptors } from "./context-mcp";
import {
  ContextRouteError,
  normalizeProjectId,
  type ContextCandidate,
} from "./context-route-support";

// ---------------------------------------------------------------------------
// Heavy IO for the context routes: auth + run + actor derivation (reuses the
// /api/llm-bridge pattern), trusted on-disk OAS slot loading, and candidate
// resolution. Kept separate from context-route-support.ts so the pure logic
// stays unit-testable without the agents / MCP import chain.
// ---------------------------------------------------------------------------

function inRepoSlug(packageName: string | null | undefined): string | null {
  if (typeof packageName !== "string") return null;
  const m = /^@cinatra-ai\/([a-z0-9][a-z0-9-]*)$/.exec(packageName);
  return m ? m[1] : null;
}

async function readInstalledOas(
  packageName: string,
): Promise<Record<string, unknown> | null> {
  const slug = inRepoSlug(packageName);
  if (!slug) return null;
  const root = resolveAgentInstallDir();
  const oasPath = join(root, "cinatra-ai", slug, "cinatra", "oas.json");
  if (!existsSync(oasPath)) return null;
  try {
    return JSON.parse(await readFile(oasPath, "utf8")) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Load + validate the trusted slot from the parent package's installed OAS.
 *  Throws ContextRouteError(404) when missing/duplicate. NEVER trusts a
 *  caller-supplied OAS body. */
export async function loadTrustedSlot(
  parentPackageName: string,
  slotId: string,
): Promise<AgentContextSlot> {
  const oas = await readInstalledOas(parentPackageName);
  if (!oas) {
    throw new ContextRouteError(
      404,
      "oas_missing",
      `no installed OAS for parent package '${parentPackageName}'`,
    );
  }
  const slots = readAgentContextSlotsFromOas(oas);
  const matches = slots.filter((s) => s.slotId === slotId);
  if (matches.length === 0) {
    throw new ContextRouteError(
      404,
      "slot_missing",
      `no contextSlot '${slotId}' on parent package '${parentPackageName}'`,
    );
  }
  if (matches.length > 1) {
    throw new ContextRouteError(
      404,
      "slot_ambiguous",
      `duplicate contextSlot '${slotId}' on '${parentPackageName}'`,
    );
  }
  return matches[0];
}

export type DerivedContext = {
  actor: ActorContext;
  run: AgentRunRecord;
  projectId: string | undefined;
  /** The trusted package name (from the run's template, NOT the body). All
   *  downstream slot loading MUST use this, never the caller-supplied value. */
  trustedPackageName: string;
};

/** Authorize the request, resolve the parent run (preferring the auth-injected
 *  context-id over the body, like /api/llm-bridge), build the run-user actor,
 *  and reject any caller-supplied parentPackageName that disagrees with the
 *  run's TEMPLATE package (forged-body defense). Throws ContextRouteError on
 *  any failure. */
export async function deriveContextRouteContext(
  req: Request,
  body: { parentRunId: string; parentPackageName: string; projectId?: unknown },
): Promise<DerivedContext> {
  // 1. Dual auth: bridge token (WayFlow TS) OR Bearer JWT (Python containers).
  if (!isAuthorizedBridgeRequest(req)) {
    const jwt = await verifyLangGraphBridgeToken(req);
    if (!jwt.ok) {
      throw new ContextRouteError(403, "forbidden", "bridge auth failed");
    }
  }
  // 2. Resolve the parent run. The auth-injected x-cinatra-a2a-context-id is
  //    the TRUSTED run binding (the context FlowNode runs inside the parent
  //    run's WayFlow conversation). Cross-check the body's parentRunId against
  //    it and reject any mismatch (defense against a forged body selecting
  //    another run). Fall back to the body id only when no context-id is
  //    present (mirrors /api/llm-bridge).
  const a2aContextId = req.headers.get("x-cinatra-a2a-context-id");
  let run: AgentRunRecord | null = null;
  if (a2aContextId) {
    // Header present ⇒ it is the TRUSTED binding. Fail CLOSED on an
    // unresolvable context-id (never fall back to the body id) and reject a
    // body parentRunId that disagrees.
    run = await readAgentRunByContextId(a2aContextId);
    if (!run) {
      throw new ContextRouteError(
        403,
        "context_unresolved",
        "x-cinatra-a2a-context-id did not resolve to a run",
      );
    }
    if (body.parentRunId && body.parentRunId !== run.id) {
      throw new ContextRouteError(
        403,
        "run_mismatch",
        `body parentRunId '${body.parentRunId}' does not match the authenticated run`,
      );
    }
  } else {
    // No context-id header ⇒ body fallback (dev loopback / first-call case,
    // matching /api/llm-bridge's own fallback behavior).
    run = await readAgentRunById(body.parentRunId);
  }
  if (!run) {
    throw new ContextRouteError(
      404,
      "run_missing",
      `parent run '${body.parentRunId}' not found`,
    );
  }
  if (!run.orgId || !run.runBy) {
    throw new ContextRouteError(
      403,
      "run_unscoped",
      "parent run has no org/runBy — refusing unscoped context resolution",
    );
  }
  // 3. Forged-body defense: derive the ALLOW-SET of trusted package names from
  //    the run's TEMPLATE (server-side; AgentRunRecord carries no packageName),
  //    then require the caller-supplied parentPackageName to be a member. A
  //    missing run package fails closed. The chosen package selects the trusted
  //    OAS slot + accepted-extension set downstream.
  const template = await readAgentTemplateById(run.templateId);
  const runPackageName = template?.packageName ?? null;
  if (!runPackageName) {
    throw new ContextRouteError(
      403,
      "package_unresolved",
      `run template '${run.templateId}' has no package name — cannot trust a slot source`,
    );
  }
  // #822: an orchestrator run resolves context slots that belong to a CHILD
  // agent it composes; that child calls context-resolve with its OWN package
  // (the slot's owner), not the run package. Accept parentPackageName when it is
  // the run package OR a package the run's template legitimately declares in
  // agentDependencies (its composed children), then trust THAT package as the
  // slot source. The allow-set is derived server-side from the run template, so
  // the forged-body defense holds — an arbitrary/undeclared package is still
  // rejected. Exact membership only: no wildcard/substring/scope-prefix/semver.
  // NOTE: this trusts any DECLARED dependency, not proof of the exact executing
  // child node; tightening to the compiled childAgent packageName is a follow-up
  // (compiled templates do not reliably carry childAgent.packageName yet).
  const declaredDeps = new Set(Object.keys(template?.agentDependencies ?? {}));
  if (
    body.parentPackageName !== runPackageName &&
    !declaredDeps.has(body.parentPackageName)
  ) {
    throw new ContextRouteError(
      403,
      "package_mismatch",
      `parentPackageName '${body.parentPackageName}' is neither the run package '${runPackageName}' nor a declared agent dependency`,
    );
  }
  // Downstream slot loading MUST use this validated value, never the raw body.
  const trustedPackageName = body.parentPackageName;
  // 4. Build the run-user actor with team + project visibility (canonical
  //    agent-run actor pattern; mirrors packages/agents mcp/handlers.ts).
  //    resolveAgentRunMcpActor returns null for a non-member/demoted run user
  //    — fail CLOSED (never default to org-scoped "member").
  const mcpActor = await resolveAgentRunMcpActor({
    runId: run.id,
    runBy: run.runBy,
    orgId: run.orgId,
  });
  if (!mcpActor) {
    throw new ContextRouteError(
      403,
      "actor_unresolved",
      "run user is not a current member of the run org — refusing context resolution",
    );
  }
  const teamIds = (await readTeamsForUser(run.runBy, run.orgId)).map((t) => t.id);
  const projectGrants = await readProjectGrantsForUser(run.runBy, run.orgId, {
    teamIds,
  });
  const actor = buildActorContextFromPrimitive(
    {
      actorType: "human",
      source: "agent",
      userId: run.runBy,
    } as Parameters<typeof buildActorContextFromPrimitive>[0],
    run.orgId,
    {
      platformRole: mcpActor.platformRole,
      actorOrganizationId: run.orgId,
      teamIds,
      projectGrants,
    },
  ) as unknown as ActorContext;

  // projectId: the run's project is authoritative; fall back to the normalized
  // body value. Normalize both (a stored "" must not fail-close the resolver).
  const projectId =
    normalizeProjectId(run.projectId) ?? normalizeProjectId(body.projectId);

  return { actor, run, projectId, trustedPackageName };
}

/** Resolve candidates for a slot via the existing resolver + server-side
 *  installed-extension discovery. */
export function resolveCandidates(input: {
  actor: ActorContext;
  slot: AgentContextSlot;
  projectId: string | undefined;
}): ContextCandidate[] {
  const refs = resolveContextSlot({
    actor: input.actor,
    slot: input.slot,
    projectId: input.projectId,
    installedExtensions: getInstalledExtensionDescriptors(),
  });
  return refs as ContextCandidate[];
}
