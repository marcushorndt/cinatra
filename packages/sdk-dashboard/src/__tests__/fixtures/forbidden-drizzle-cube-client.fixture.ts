// FIXTURE — ESLint should flag this. Imports drizzle-cube/client/* anywhere
// in the repo (this rule applies globally, not just to sdk-dashboard) —
// violates the shadcn-admin "no exceptions" UI rule.
//
// eslint-disable-next-line no-unused-vars
import { AnalyticsPortlet } from "drizzle-cube/client/components";

export const used = AnalyticsPortlet;
