import type {
  AuthClientResult,
  AuthRequest,
  AuthTransport,
} from "@ngriffin_uk/auth-react";

import {
  authenticateWithPassword,
  executeMfaVerification,
  executeSecuritySetup,
  resumePendingMfa,
  signOutDemo,
  type DemoUser,
} from "./api.ts";

export const demoAuthTransport: AuthTransport<DemoUser> = {
  async execute(
    request: AuthRequest,
  ): Promise<AuthClientResult<DemoUser>> {
    if (request.action === "sign_in" || request.action === "sign_up") {
      const email = request.values.email;
      const password = request.values.password;
      if (typeof email !== "string" || typeof password !== "string") {
        throw new Error("Enter an email address and password.");
      }
      return authenticateWithPassword(
        request.action === "sign_in" ? "sign-in" : "sign-up",
        { email, password },
      );
    }

    if (request.action === "start_oauth") {
      if (
        request.provider !== "amazon-cognito" &&
        request.provider !== "github"
      ) {
        throw new Error("This provider is not available.");
      }
      return {
        status: "redirect_required",
        provider: request.provider,
        url: `/api/oauth/${request.provider}/start`,
      };
    }

    if (request.action === "start_totp_setup") {
      return executeSecuritySetup("totp/start");
    }

    if (request.action === "start_webauthn_registration") {
      return executeSecuritySetup("webauthn/start");
    }

    if (request.action === "resume_mfa") {
      return resumePendingMfa();
    }

    if (request.action === "continue" && request.kind === "mfa_setup") {
      return executeSecuritySetup("totp/verify", {
        token: request.continuationToken,
        code: request.values.code,
      });
    }

    if (
      request.action === "continue" &&
      request.kind === "webauthn" &&
      request.values.ceremony === "registration"
    ) {
      return executeSecuritySetup("webauthn/verify", {
        token: request.continuationToken,
        credentialId: request.values.credentialId,
        clientDataJSON: request.values.clientDataJSON,
        attestationObject: request.values.attestationObject,
        transports: parseTransports(request.values.transports),
      });
    }

    if (
      request.action === "continue" &&
      request.kind === "webauthn" &&
      request.values.ceremony === "authentication"
    ) {
      return executeMfaVerification("webauthn", {
        token: request.continuationToken,
        credentialId: request.values.credentialId,
        clientDataJSON: request.values.clientDataJSON,
        authenticatorData: request.values.authenticatorData,
        signature: request.values.signature,
        ...(request.values.userHandle
          ? { userHandle: request.values.userHandle }
          : {}),
      });
    }

    if (
      request.action === "continue" &&
      request.kind === "software_token_mfa"
    ) {
      return executeMfaVerification("totp", {
        token: request.continuationToken,
        code: request.values.code,
      });
    }

    if (request.action === "sign_out") {
      await signOutDemo();
      return { status: "completed" };
    }

    throw new Error("This authentication flow is not enabled in the demo.");
  },
};

function parseTransports(value: string | undefined): readonly string[] {
  if (!value) return [];
  const transports: unknown = JSON.parse(value);
  if (
    !Array.isArray(transports) ||
    transports.some((transport) => typeof transport !== "string")
  ) {
    throw new Error("The passkey response was invalid.");
  }
  return transports;
}
