// -----------------------------------------------------------------------------
// Approved-instance-namespaces loader.
//
// Reads a config file whose path is given by CINATRA_APPROVED_INSTANCE_NAMESPACES_FILE.
// Each non-empty, non-comment line is one EXACT namespace that bypasses the
// reserved-substring guard in validator.ts.
//
// This lets an operator pre-approve specific instance names (e.g. cinatra-ai)
// via the env-pointed file. If you also run a registry that enforces reserved
// names, point both at the same file so the two sides stay in sync — there is
// then no way the app accepts a namespace the registry would reject.
//
// Pure I/O on first call per process; cached thereafter. Re-reads require a
// process restart, same as every other env-driven config in this image.
// -----------------------------------------------------------------------------

import { readFileSync } from "node:fs";

let cache: readonly string[] | undefined;

export function getApprovedInstanceNamespaces(): readonly string[] {
  if (cache !== undefined) return cache;
  const filePath = process.env.CINATRA_APPROVED_INSTANCE_NAMESPACES_FILE?.trim();
  if (!filePath) {
    cache = [];
    return cache;
  }
  try {
    cache = readFileSync(filePath, "utf8")
      .split("\n")
      .map((line) => line.trim().toLowerCase())
      .filter((line) => line.length > 0 && !line.startsWith("#"));
  } catch {
    // File missing / unreadable — fall back to the conservative empty list.
    // The validator still enforces RESERVED_SUBSTRINGS so no security gap.
    cache = [];
  }
  return cache;
}
