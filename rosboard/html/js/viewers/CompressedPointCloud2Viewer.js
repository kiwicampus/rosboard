"use strict";

// Renders point_cloud_interfaces/msg/CompressedPointCloud2 messages.
// The cloudini-compressed bytes travel over the network as-is (rosboard's
// backend does not decode them); decoding happens here, client-side, via
// the cloudini WASM module, only once the data has already reached the
// browser. See PointCloud2Viewer._renderFromRawBuffer for the shared
// rendering path once bytes are decoded.
class CompressedPointCloud2Viewer extends PointCloud2Viewer {
  static _wasmModulePromise = null;

  static _getWasmModule() {
    if (!CompressedPointCloud2Viewer._wasmModulePromise) {
      CompressedPointCloud2Viewer._wasmModulePromise = CloudiniModule();
    }
    return CompressedPointCloud2Viewer._wasmModulePromise;
  }

  onData(msg) {
    this.card.title.text(msg._topic_name);

    if (msg.width * msg.height === 0) {
      return;
    }

    CompressedPointCloud2Viewer._getWasmModule().then((wasmModule) => {
      this._decodeAndRender(wasmModule, msg);
    }).catch((error) => {
      this.error("Failed to load cloudini WASM module: " + String(error));
    });
  }

  _decodeAndRender(wasmModule, msg) {
    const compressedData = new Uint8Array(this._base64decode(msg.compressed_data));
    const decompressedSize = msg.height * msg.width * msg.point_step;

    let inputPtr = null;
    let outputPtr = null;

    try {
      inputPtr = wasmModule._malloc(compressedData.byteLength);
      if (!inputPtr) {
        this.error("cloudini: failed to allocate WASM input buffer");
        return;
      }
      new Uint8Array(wasmModule.HEAPU8.buffer, inputPtr, compressedData.byteLength).set(compressedData);

      outputPtr = wasmModule._malloc(decompressedSize);
      if (!outputPtr) {
        this.error("cloudini: failed to allocate WASM output buffer");
        return;
      }

      const actualSize = wasmModule._cldn_DecodeCompressedData(inputPtr, compressedData.byteLength, outputPtr);
      if (actualSize === 0) {
        this.error("cloudini: decompression failed");
        return;
      }

      // copy out of WASM memory before freeing it
      const decoded = wasmModule.HEAPU8.slice(outputPtr, outputPtr + actualSize);
      this._renderFromRawBuffer(msg, decoded.buffer);
    } finally {
      if (inputPtr !== null) wasmModule._free(inputPtr);
      if (outputPtr !== null) wasmModule._free(outputPtr);
    }
  }
}

// advertise this viewer to the system

CompressedPointCloud2Viewer.friendlyName = "Point cloud (3D, cloudini)";
CompressedPointCloud2Viewer.supportedTypes = [
    "point_cloud_interfaces/msg/CompressedPointCloud2",
];
CompressedPointCloud2Viewer.maxUpdateRate = 30.0;
Viewer.registerViewer(CompressedPointCloud2Viewer);
