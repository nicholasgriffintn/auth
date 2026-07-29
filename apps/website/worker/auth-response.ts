import {
  AuthError,
  type AuthFlowResult,
} from "@ngriffin_uk/auth-core";

import {
  json,
  publicUser,
  sessionCookie,
} from "./http.ts";
import type { DemoUser } from "./types";

export function authFlowResponse(result: AuthFlowResult<DemoUser>): Response {
  if (result.status === "authenticated") {
    return json(
      {
        status: result.status,
        user: publicUser(result.session.user),
      },
      200,
      {
        "Set-Cookie": sessionCookie(
          result.session.token,
          result.session.expiresAt,
        ),
      },
    );
  }
  if ("challenge" in result) {
    return json({
      status: result.status,
      challenge: {
        ...result.challenge,
        expiresAt: result.challenge.expiresAt.toISOString(),
      },
    });
  }
  throw new AuthError("unsupported_operation");
}
