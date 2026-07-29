export function ecdsaDerToRaw(signature: Uint8Array, coordinateSize: number): Uint8Array {
  let offset = 0;
  if (signature[offset++] !== 0x30) throw new TypeError("Invalid ECDSA signature.");
  const sequence = readLength(signature, offset);
  offset = sequence.offset;
  if (offset + sequence.length !== signature.length) {
    throw new TypeError("Invalid ECDSA signature length.");
  }
  const r = readInteger(signature, offset);
  const s = readInteger(signature, r.offset);
  if (s.offset !== signature.length) throw new TypeError("Invalid ECDSA signature.");
  const output = new Uint8Array(coordinateSize * 2);
  copyInteger(r.value, output, 0, coordinateSize);
  copyInteger(s.value, output, coordinateSize, coordinateSize);
  return output;
}

function readInteger(
  input: Uint8Array,
  offset: number
): { readonly value: Uint8Array; readonly offset: number } {
  if (input[offset++] !== 0x02) throw new TypeError("Invalid ECDSA integer.");
  const decoded = readLength(input, offset);
  const end = decoded.offset + decoded.length;
  if (decoded.length === 0 || end > input.length) {
    throw new TypeError("Invalid ECDSA integer length.");
  }
  let value = input.slice(decoded.offset, end);
  if ((value[0]! & 0x80) !== 0) {
    throw new TypeError("ECDSA integers must be positive.");
  }
  if (value.length > 1 && value[0] === 0) {
    if ((value[1]! & 0x80) === 0) {
      throw new TypeError("ECDSA integer has unnecessary padding.");
    }
    value = value.slice(1);
  }
  return { value, offset: end };
}

function readLength(
  input: Uint8Array,
  offset: number
): { readonly length: number; readonly offset: number } {
  const initial = input[offset++];
  if (initial === undefined) throw new TypeError("Invalid DER length.");
  if (initial < 0x80) return { length: initial, offset };
  const bytes = initial & 0x7f;
  if (bytes === 0 || bytes > 4 || offset + bytes > input.length) {
    throw new TypeError("Invalid DER length.");
  }
  let length = 0;
  for (let index = 0; index < bytes; index += 1) {
    length = length * 256 + input[offset + index]!;
  }
  if (length < 0x80) throw new TypeError("DER length is not minimally encoded.");
  return { length, offset: offset + bytes };
}

function copyInteger(
  value: Uint8Array,
  output: Uint8Array,
  offset: number,
  size: number
): void {
  if (value.length > size) throw new TypeError("ECDSA integer is too large.");
  output.set(value, offset + size - value.length);
}
