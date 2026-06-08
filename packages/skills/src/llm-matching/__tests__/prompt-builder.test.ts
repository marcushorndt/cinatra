import { describe, it, expect } from "vitest";
import { buildPromptForPair } from "../prompt-builder";
import { SKILL_MATCH_MAX_INPUT_TOKENS_PER_PAIR } from "../constants";
import type { AgentForMatching, SkillForMatching } from "../types";

const baseAgent: AgentForMatching = {
  packageId: "@cinatra/email-agent",
  name: "Email Agent",
  description: "Sends marketing emails to leads",
  tags: ["email", "outreach"],
};

const baseSkill: SkillForMatching = {
  skillId: "skill-write-email",
  name: "write-email",
  level: "system",
  content: "Use this skill to compose marketing emails.",
};

describe("prompt-builder", () => {
  it("rendered prompt contains agent.name, agent.description, skill.name, skill.content", () => {
    const { system, user } = buildPromptForPair(baseAgent, baseSkill);
    const combined = `${system}\n${user}`;
    expect(combined).toContain("Email Agent");
    expect(combined).toContain("Sends marketing emails to leads");
    expect(combined).toContain("write-email");
    expect(combined).toContain("Use this skill to compose marketing emails.");
  });

  it("agent.tags array is rendered as comma-separated string", () => {
    const { user } = buildPromptForPair(baseAgent, baseSkill);
    expect(user).toMatch(/email,\s*outreach/);
  });

  it("undefined matchWhenRaw renders as '(none)' (never raw {{matchWhenHint}})", () => {
    const { system, user } = buildPromptForPair(baseAgent, { ...baseSkill, matchWhenRaw: undefined });
    const combined = `${system}\n${user}`;
    expect(combined).toContain("(none)");
    expect(combined).not.toContain("{{matchWhenHint}}");
  });

  it("oversized SKILL.md content is truncated with [truncated] marker", () => {
    const huge = "X".repeat(SKILL_MATCH_MAX_INPUT_TOKENS_PER_PAIR * 4 + 1000);
    const { user } = buildPromptForPair(baseAgent, { ...baseSkill, content: huge });
    expect(user).toContain("[truncated]");
  });

  it("rendered prompt has no unsubstituted Mustache placeholders", () => {
    const { system, user } = buildPromptForPair(baseAgent, {
      ...baseSkill,
      matchWhenRaw: "- always",
    });
    const combined = `${system}\n${user}`;
    expect(combined).not.toContain("{{");
    expect(combined).not.toContain("}}");
  });
});
