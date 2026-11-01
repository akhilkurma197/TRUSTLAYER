export function viewportFixtureCssPosition(imageBox, workerPoint, viewport = { width: 1280, height: 800 }) {
  if (!imageBox || !Number.isFinite(imageBox.width) || !Number.isFinite(imageBox.height) ||
      imageBox.width <= 0 || imageBox.height <= 0 || !workerPoint ||
      !Number.isFinite(workerPoint.x) || !Number.isFinite(workerPoint.y) ||
      workerPoint.x < 0 || workerPoint.x > viewport.width || workerPoint.y < 0 || workerPoint.y > viewport.height) {
    throw new TypeError('A visible viewport box and in-bounds worker point are required.');
  }
  return {
    x: workerPoint.x / viewport.width * imageBox.width,
    y: workerPoint.y / viewport.height * imageBox.height
  };
}
