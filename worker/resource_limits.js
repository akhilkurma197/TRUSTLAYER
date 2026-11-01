export const MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024;
export const MAX_EVENT_RECORDS = 512;
export const MAX_RESULT_BYTES = 2 * 1024 * 1024;
export const MAX_TEXT_FIELD_CHARS = 2048;

export function appendBounded(records, record, limit = MAX_EVENT_RECORDS) {
  if (records.length < limit) records.push(record);
}

export function isBoundedPng(buffer) {
  return Buffer.isBuffer(buffer) && buffer.length >= 1000 && buffer.length <= MAX_SCREENSHOT_BYTES &&
    buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) &&
    buffer.readUInt32BE(16) > 0 && buffer.readUInt32BE(16) <= 1280 &&
    buffer.readUInt32BE(20) > 0 && buffer.readUInt32BE(20) <= 800;
}

export function serializeBoundedJson(value, maxBytes = MAX_RESULT_BYTES) {
  const serialized = JSON.stringify(value);
  if (Buffer.byteLength(serialized, 'utf8') > maxBytes) {
    throw new RangeError(`Worker result exceeds ${maxBytes} byte output limit.`);
  }
  return serialized;
}
