import type { AuthClientChallenge } from "@ngriffin_uk/auth-react";
import {
  decodeBase64Url,
  encodeBase64Url,
} from "@ngriffin_uk/auth-encoding";

import { toArrayBuffer } from "../../shared/bytes.ts";

const algorithmIdentifiers: Readonly<Record<string, number>> = {
  ES256: -7,
  RS256: -257,
};

export async function resolveWebAuthnChallenge(
  challenge: AuthClientChallenge,
): Promise<Readonly<Record<string, string>>> {
  if (challenge.kind !== "webauthn") {
    throw new Error("This passkey operation is not supported.");
  }
  if (typeof PublicKeyCredential === "undefined" || !navigator.credentials) {
    throw new Error("Passkeys are not supported by this browser.");
  }

  if (challenge.parameters?.ceremony === "authentication") {
    const credential = await navigator.credentials.get({
      publicKey: createWebAuthnAuthenticationOptions(challenge),
    });
    if (
      !(credential instanceof PublicKeyCredential) ||
      !(credential.response instanceof AuthenticatorAssertionResponse)
    ) {
      throw new Error("The browser did not return a passkey assertion.");
    }
    return {
      ceremony: "authentication",
      credentialId: encodeBase64Url(new Uint8Array(credential.rawId)),
      clientDataJSON: encodeBase64Url(
        new Uint8Array(credential.response.clientDataJSON),
      ),
      authenticatorData: encodeBase64Url(
        new Uint8Array(credential.response.authenticatorData),
      ),
      signature: encodeBase64Url(
        new Uint8Array(credential.response.signature),
      ),
      ...(credential.response.userHandle
        ? {
          userHandle: encodeBase64Url(
            new Uint8Array(credential.response.userHandle),
          ),
        }
        : {}),
    };
  }

  const credential = await navigator.credentials.create({
    publicKey: createWebAuthnRegistrationOptions(challenge),
  });

  if (
    !(credential instanceof PublicKeyCredential) ||
    !(credential.response instanceof AuthenticatorAttestationResponse)
  ) {
    throw new Error("The browser did not return a passkey registration.");
  }
  return {
    ceremony: "registration",
    credentialId: encodeBase64Url(new Uint8Array(credential.rawId)),
    clientDataJSON: encodeBase64Url(
      new Uint8Array(credential.response.clientDataJSON),
    ),
    attestationObject: encodeBase64Url(
      new Uint8Array(credential.response.attestationObject),
    ),
    transports: JSON.stringify(credential.response.getTransports()),
  };
}

export function createWebAuthnAuthenticationOptions(
  challenge: AuthClientChallenge,
): PublicKeyCredentialRequestOptions {
  if (
    challenge.kind !== "webauthn" ||
    challenge.parameters?.ceremony !== "authentication"
  ) {
    throw new Error("This passkey operation is not supported.");
  }
  const parameters = challenge.parameters;
  const allowCredentialIds = parameters.allowCredentialIds;
  return {
    challenge: toArrayBuffer(
      new TextEncoder().encode(requiredParameter(parameters, "challenge")),
    ),
    rpId: requiredParameter(parameters, "rpId"),
    timeout: timeout(parameters.timeout),
    userVerification: userVerification(parameters.userVerification),
    ...(Array.isArray(allowCredentialIds)
      ? {
        allowCredentials: allowCredentialIds.map((id) => ({
          id: toArrayBuffer(decodeBase64Url(id)),
          type: "public-key",
        })),
      }
      : {}),
  };
}

export function createWebAuthnRegistrationOptions(
  challenge: AuthClientChallenge,
): PublicKeyCredentialCreationOptions {
  if (
    challenge.kind !== "webauthn" ||
    challenge.parameters?.ceremony !== "registration"
  ) {
    throw new Error("This passkey operation is not supported.");
  }
  const parameters = challenge.parameters;
  return {
    attestation: attestation(parameters.attestation),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "required",
    },
    challenge: toArrayBuffer(
      new TextEncoder().encode(requiredParameter(parameters, "challenge")),
    ),
    pubKeyCredParams: algorithms(parameters.algorithms),
    rp: {
      id: requiredParameter(parameters, "rpId"),
      name: requiredParameter(parameters, "rpName"),
    },
    timeout: timeout(parameters.timeout),
    user: {
      id: toArrayBuffer(
        decodeBase64Url(requiredParameter(parameters, "userId")),
      ),
      name: requiredParameter(parameters, "userName"),
      displayName: requiredParameter(parameters, "displayName"),
    },
  };
}

function requiredParameter(
  parameters: Readonly<Record<string, string | readonly string[]>>,
  name: string,
): string {
  const value = parameters[name];
  if (typeof value !== "string" || !value) {
    throw new Error("The passkey challenge is incomplete.");
  }
  return value;
}

function algorithms(
  value: string | readonly string[] | undefined,
): PublicKeyCredentialParameters[] {
  if (!Array.isArray(value)) {
    throw new Error("The passkey algorithms are missing.");
  }
  const values = value.flatMap((name) => {
    const alg = algorithmIdentifiers[name];
    return alg === undefined ? [] : [{ alg, type: "public-key" as const }];
  });
  if (values.length === 0) {
    throw new Error("The passkey algorithms are not supported.");
  }
  return values;
}

function timeout(value: string | readonly string[] | undefined): number {
  if (
    typeof value !== "string" ||
    !/^\d+$/u.test(value) ||
    Number(value) < 1 ||
    Number(value) > 600_000
  ) {
    throw new Error("The passkey timeout is invalid.");
  }
  return Number(value);
}

function attestation(
  value: string | readonly string[] | undefined,
): AttestationConveyancePreference {
  if (value === "none" || value === "direct") return value;
  throw new Error("The passkey attestation preference is invalid.");
}

function userVerification(
  value: string | readonly string[] | undefined,
): UserVerificationRequirement {
  if (value === "required" || value === "preferred") return value;
  throw new Error("The passkey user verification preference is invalid.");
}
