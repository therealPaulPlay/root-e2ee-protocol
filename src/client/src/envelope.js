import { Encoder } from "cbor-x";

// int64AsNumber avoids BigInt values that break Date() and other JS APIs
// Cast: the option exists at runtime but is missing from cbor-x's type definitions
/** @type {import("cbor-x").Options & { int64AsNumber?: boolean }} */
const cborOptions = { useRecords: false, mapsAsObjects: true, int64AsNumber: true };
export const cbor = new Encoder(cborOptions);

/**
 * @typedef {Object} Envelope
 * @property {string} type
 * @property {string} originId
 * @property {string} targetId
 * @property {string} requestId
 * @property {Uint8Array} payload encrypted or plaintext CBOR bytes
 */
