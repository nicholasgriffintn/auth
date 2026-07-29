const MAX_CBOR_BYTES = 1_048_576;
const MAX_CBOR_DEPTH = 12;

type CborScalar = bigint | boolean | null | number | string | Uint8Array;
export type CborValue =
  | CborScalar
  | readonly CborValue[]
  | ReadonlyMap<CborScalar, CborValue>;

interface DecodeResult {
  readonly value: CborValue;
  readonly offset: number;
}

export function decodeCbor(input: Uint8Array): CborValue {
  if (input.length === 0 || input.length > MAX_CBOR_BYTES) {
    throw new TypeError("CBOR input has an invalid size.");
  }
  const decoded = decodeItem(input, 0, 0);
  if (decoded.offset !== input.length) {
    throw new TypeError("CBOR input contains trailing data.");
  }
  return decoded.value;
}

function decodeItem(
  input: Uint8Array,
  offset: number,
  depth: number
): DecodeResult {
  if (depth > MAX_CBOR_DEPTH || offset >= input.length) {
    throw new TypeError("CBOR input is malformed.");
  }
  const initial = input[offset]!;
  const major = initial >>> 5;
  const additional = initial & 31;
  const length = decodeLength(input, offset + 1, additional);

  if (major === 0) {
    return { value: integerValue(length.value), offset: length.offset };
  }
  if (major === 1) {
    const value = length.value;
    return {
      value:
        value <= BigInt(Number.MAX_SAFE_INTEGER)
          ? -1 - Number(value)
          : -1n - value,
      offset: length.offset,
    };
  }
  if (major === 2 || major === 3) {
    const byteLength = safeLength(length.value);
    const end = length.offset + byteLength;
    if (end > input.length) throw new TypeError("CBOR input is truncated.");
    const bytes = input.slice(length.offset, end);
    return {
      value:
        major === 2
          ? bytes
          : new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      offset: end,
    };
  }
  if (major === 4) {
    const itemCount = safeLength(length.value);
    const values: CborValue[] = [];
    let cursor = length.offset;
    for (let index = 0; index < itemCount; index += 1) {
      const item = decodeItem(input, cursor, depth + 1);
      values.push(item.value);
      cursor = item.offset;
    }
    return { value: values, offset: cursor };
  }
  if (major === 5) {
    const itemCount = safeLength(length.value);
    const values = new Map<CborScalar, CborValue>();
    let cursor = length.offset;
    for (let index = 0; index < itemCount; index += 1) {
      const key = decodeItem(input, cursor, depth + 1);
      if (!isScalar(key.value)) {
        throw new TypeError("CBOR map keys must be scalar values.");
      }
      const item = decodeItem(input, key.offset, depth + 1);
      if (values.has(key.value)) {
        throw new TypeError("CBOR map contains a duplicate key.");
      }
      values.set(key.value, item.value);
      cursor = item.offset;
    }
    return { value: values, offset: cursor };
  }
  if (major === 7 && additional === 20) {
    return { value: false, offset: offset + 1 };
  }
  if (major === 7 && additional === 21) {
    return { value: true, offset: offset + 1 };
  }
  if (major === 7 && additional === 22) {
    return { value: null, offset: offset + 1 };
  }
  throw new TypeError("Unsupported CBOR value.");
}

function decodeLength(
  input: Uint8Array,
  offset: number,
  additional: number
): { readonly value: bigint; readonly offset: number } {
  if (additional < 24) {
    return { value: BigInt(additional), offset };
  }
  const bytes = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
  if (bytes === 0 || offset + bytes > input.length) {
    throw new TypeError("CBOR length is malformed.");
  }
  let value = 0n;
  for (let index = 0; index < bytes; index += 1) {
    value = (value << 8n) | BigInt(input[offset + index]!);
  }
  return { value, offset: offset + bytes };
}

function safeLength(value: bigint): number {
  if (value > BigInt(MAX_CBOR_BYTES)) {
    throw new TypeError("CBOR collection is too large.");
  }
  return Number(value);
}

function integerValue(value: bigint): number | bigint {
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value;
}

function isScalar(value: CborValue): value is CborScalar {
  return (
    typeof value === "bigint" ||
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "string" ||
    value === null ||
    value instanceof Uint8Array
  );
}

export function cborMap(
  value: CborValue | undefined,
  field: string
): ReadonlyMap<CborScalar, CborValue> {
  if (!(value instanceof Map)) {
    throw new TypeError(`${field} must be a CBOR map.`);
  }
  return value;
}

export function cborBytes(value: CborValue | undefined, field: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${field} must be a CBOR byte string.`);
  }
  return value;
}

export function cborString(value: CborValue | undefined, field: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a CBOR string.`);
  }
  return value;
}

export function cborNumber(value: CborValue | undefined, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new TypeError(`${field} must be a CBOR integer.`);
  }
  return value;
}
