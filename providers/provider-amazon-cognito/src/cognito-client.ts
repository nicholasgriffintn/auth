import { AuthError } from "@ngriffin_uk/auth-core";
import { hmac } from "@ngriffin_uk/auth-crypto";
import { encodeBase64 } from "@ngriffin_uk/auth-encoding";
import {
  readResponseText,
  requestWithTimeout,
} from "@ngriffin_uk/auth-request";

const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const textEncoder = new TextEncoder();

export class CognitoServiceError extends Error {
  readonly type: string;

  constructor(type: string, options?: { readonly cause?: unknown }) {
    super("Amazon Cognito rejected the request.", {
      cause: options?.cause,
    });
    this.name = "CognitoServiceError";
    this.type = type;
  }
}

export interface CognitoClientOptions {
  readonly region: string;
  readonly clientId: string;
  readonly clientSecret?: string;
  readonly endpoint?: string;
  readonly fetch?: typeof globalThis.fetch;
  readonly maxResponseBytes?: number;
  readonly requestTimeoutMs?: number;
}

export class CognitoClient {
  readonly clientId: string;
  readonly #clientSecret: string | undefined;
  readonly #endpoint: URL;
  readonly #fetch: typeof globalThis.fetch;
  readonly #maxResponseBytes: number;
  readonly #requestTimeoutMs: number;

  constructor(options: CognitoClientOptions) {
    if (!/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/u.test(options.region)) {
      throw new TypeError("Amazon Cognito region is invalid.");
    }
    if (!/^[\w+]{1,128}$/u.test(options.clientId)) {
      throw new TypeError("Amazon Cognito client ID is invalid.");
    }
    this.clientId = options.clientId;
    this.#clientSecret = options.clientSecret;
    this.#endpoint = validateEndpoint(
      options.endpoint ??
        `https://cognito-idp.${options.region}.amazonaws.com/`
    );
    const request = options.fetch ?? globalThis.fetch;
    if (!request) throw new AuthError("unsupported_operation", "Fetch is unavailable.");
    this.#fetch = request;
    this.#maxResponseBytes = positiveInteger(
      options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
      "Amazon Cognito response size"
    );
    this.#requestTimeoutMs = positiveInteger(
      options.requestTimeoutMs ?? DEFAULT_TIMEOUT_MS,
      "Amazon Cognito request timeout"
    );
  }

  async request(
    operation: string,
    body: Readonly<Record<string, unknown>>
  ): Promise<Readonly<Record<string, unknown>>> {
    let response: Response;
    try {
      response = await requestWithTimeout(
        this.#fetch,
        this.#endpoint,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/x-amz-json-1.0",
            "X-Amz-Target": `AWSCognitoIdentityProviderService.${operation}`,
          },
          body: JSON.stringify(body),
          redirect: "error",
        },
        this.#requestTimeoutMs
      );
    } catch (cause) {
      throw new AuthError("provider_error", undefined, {
        cause,
        retryable: true,
      });
    }
    let text: string;
    try {
      text = await readResponseText(response, this.#maxResponseBytes);
    } catch (cause) {
      throw new AuthError("provider_error", undefined, { cause });
    }
    let value: unknown = {};
    if (text) {
      try {
        value = JSON.parse(text);
      } catch (cause) {
        throw new AuthError("provider_error", undefined, { cause });
      }
    }
    if (!response.ok) {
      throw new CognitoServiceError(readErrorType(value));
    }
    if (!isRecord(value)) {
      throw new AuthError("provider_error");
    }
    return value;
  }

  async secretHash(username: string): Promise<string | undefined> {
    if (!this.#clientSecret) return undefined;
    const signature = await hmac(
      "SHA-256",
      textEncoder.encode(this.#clientSecret),
      textEncoder.encode(username + this.clientId)
    );
    return encodeBase64(signature);
  }

  clientSecret(): string | undefined {
    return this.#clientSecret;
  }
}

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive integer.`);
  }
  return value;
}

function readErrorType(value: unknown): string {
  if (!isRecord(value)) return "UnknownException";
  const raw =
    typeof value["__type"] === "string"
      ? value["__type"]
      : typeof value["code"] === "string"
        ? value["code"]
        : "UnknownException";
  return raw.split(/[#/:]/u).at(-1) ?? "UnknownException";
}

function validateEndpoint(value: string): URL {
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new TypeError("Amazon Cognito endpoint must be a secure HTTPS URL.");
  }
  return url;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
