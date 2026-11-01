import { createHash } from 'node:crypto';

export async function readDisplayedViewportFrame(imageLocator) {
  const frame = await imageLocator.evaluate(async image => {
    const source = image.currentSrc || image.src;
    if (!source.startsWith('blob:')) return null;
    const response = await fetch(source);
    if (!response.ok) return null;
    const blob = await response.blob();
    const data = new Uint8Array(await blob.arrayBuffer());
    let binary = '';
    for (let offset = 0; offset < data.length; offset += 8192) {
      binary += String.fromCharCode(...data.subarray(offset, offset + 8192));
    }
    return { type: blob.type, bytes: blob.size, base64: btoa(binary), width: image.naturalWidth, height: image.naturalHeight };
  });
  if (!frame) return null;
  const bytes = Buffer.from(frame.base64, 'base64');
  return { type: frame.type, bytes: frame.bytes, sha256: bytes.length ? createHash('sha256').update(bytes).digest('hex') : null,
    width: frame.width, height: frame.height };
}
