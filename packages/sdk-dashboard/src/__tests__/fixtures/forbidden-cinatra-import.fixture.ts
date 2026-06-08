// FIXTURE — ESLint should flag this. Imports a Cinatra-app module from
// inside sdk-dashboard, which is forbidden.
//
// eslint-disable-next-line no-unused-vars
import { somethingFromHost } from "@/lib/auth-session";

export const used = somethingFromHost;
