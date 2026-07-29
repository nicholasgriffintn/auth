import { AuthError } from "@ngriffin_uk/auth-core";
import type {
  WebAuthnAuthenticationResponse,
  WebAuthnRegistrationResponse,
} from "@ngriffin_uk/auth-webauthn";

import { optionalString, requiredString } from "./input.ts";

const MAX_AUTHENTICATOR_TRANSPORTS = 5;

export function registrationResponse(
  body: Readonly<Record<string, unknown>>,
): WebAuthnRegistrationResponse {
  const transports = optionalTransports(body.transports);
  return {
    credentialId: requiredString(body, "credentialId", 16_384),
    clientDataJSON: requiredString(body, "clientDataJSON", 65_536),
    attestationObject: requiredString(body, "attestationObject", 65_536),
    ...(transports ? { transports } : {}),
  };
}

export function authenticationResponse(
  body: Readonly<Record<string, unknown>>,
): WebAuthnAuthenticationResponse {
  const userHandle = optionalString(body, "userHandle", 128);
  return {
    credentialId: requiredString(body, "credentialId", 16_384),
    clientDataJSON: requiredString(body, "clientDataJSON", 65_536),
    authenticatorData: requiredString(body, "authenticatorData", 16_384),
    signature: requiredString(body, "signature", 16_384),
    ...(userHandle ? { userHandle } : {}),
  };
}

function optionalTransports(
  value: unknown,
): readonly AuthenticatorTransport[] | undefined {
  if (value === undefined) return undefined;
  if (
    !isAuthenticatorTransports(value) ||
    value.length > MAX_AUTHENTICATOR_TRANSPORTS ||
    new Set(value).size !== value.length
  ) {
    throw new AuthError("invalid_input");
  }
  return value;
}

function isAuthenticatorTransports(
  value: unknown,
): value is readonly AuthenticatorTransport[] {
  return (
    Array.isArray(value) &&
    value.every(
      (transport) =>
        typeof transport === "string" &&
        isAuthenticatorTransport(transport),
    )
  );
}

function isAuthenticatorTransport(
  value: string,
): value is AuthenticatorTransport {
  return (
    value === "ble" ||
    value === "hybrid" ||
    value === "internal" ||
    value === "nfc" ||
    value === "usb"
  );
}
