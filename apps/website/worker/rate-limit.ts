import { AuthError } from "@ngriffin_uk/auth-core";

import type { Env } from "./types";

export async function assertAuthRateLimit(
  request: Request,
  env: Pick<Env, "AUTH_RATE_LIMIT">,
  operation: string,
): Promise<void> {
  const actor = request.headers.get("CF-Connecting-IP") ?? "local";
  const result = await env.AUTH_RATE_LIMIT.limit({
    key: `${operation}:${actor}`,
  });
  if (!result.success) throw new AuthError("rate_limited");
}
