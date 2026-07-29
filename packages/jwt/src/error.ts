import type { JwtErrorCode } from "./types.js";

export class JwtError extends Error {
  readonly code: JwtErrorCode;

  constructor(code: JwtErrorCode, message: string, options?: { cause: unknown }) {
    super(message, options);
    this.name = "JwtError";
    this.code = code;
  }
}
