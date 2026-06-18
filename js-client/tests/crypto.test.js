import { describe, test, expect } from "vitest";
import { generateKeypairP256, deriveSessionP256 } from "../src/crypto.js";

describe("generateKeypairP256", () => {
	test("produces a raw uncompressed SEC1 public key (65 bytes, leading 0x04) and a PKCS8 private key", async () => {
		const { publicKey, privateKey } = await generateKeypairP256();
		expect(publicKey).toBeInstanceOf(Uint8Array);
		expect(privateKey).toBeInstanceOf(Uint8Array);
		expect(publicKey.length).toBe(65);
		expect(publicKey[0]).toBe(0x04);
		expect(privateKey.length).toBeGreaterThan(32); // PKCS8 DER is structured, always > raw
	});

	test("produces unique keypairs", async () => {
		const a = await generateKeypairP256();
		const b = await generateKeypairP256();
		expect(a.publicKey).not.toEqual(b.publicKey);
		expect(a.privateKey).not.toEqual(b.privateKey);
	});
});

describe("deriveSessionP256", () => {
	test("produces a symmetric session: alice(aPriv, bPub) can decrypt what bob(bPriv, aPub) encrypted", async () => {
		const a = await generateKeypairP256();
		const b = await generateKeypairP256();
		const alice = await deriveSessionP256(a.privateKey, b.publicKey);
		const bob = await deriveSessionP256(b.privateKey, a.publicKey);

		const plaintext = new TextEncoder().encode("hello");
		const ciphertext = await bob.encrypt(plaintext);
		const recovered = await alice.decrypt(ciphertext);
		expect(recovered).toEqual(plaintext);
	});
});

describe("SessionAES256GCM", () => {
	async function makePair() {
		const a = await generateKeypairP256();
		const b = await generateKeypairP256();
		return {
			alice: await deriveSessionP256(a.privateKey, b.publicKey),
			bob: await deriveSessionP256(b.privateKey, a.publicKey)
		};
	}

	test("prepends a unique 12-byte nonce per encryption", async () => {
		const { alice } = await makePair();
		const data = new TextEncoder().encode("x");
		const c1 = await alice.encrypt(data);
		const c2 = await alice.encrypt(data);
		expect(c1.slice(0, 12)).not.toEqual(c2.slice(0, 12));
	});

	test("binds AAD: decryption fails when AAD differs from encryption", async () => {
		const { alice, bob } = await makePair();
		const data = new TextEncoder().encode("x");
		const aad = new Uint8Array([1, 2, 3]);
		const ciphertext = await alice.encrypt(data, aad);
		await expect(bob.decrypt(ciphertext, new Uint8Array([9, 9, 9]))).rejects.toThrow();
	});

	test("rejects tampered ciphertext", async () => {
		const { alice, bob } = await makePair();
		const ciphertext = await alice.encrypt(new TextEncoder().encode("x"));
		ciphertext[ciphertext.length - 1] ^= 1;
		await expect(bob.decrypt(ciphertext)).rejects.toThrow();
	});

	test("handles empty plaintext", async () => {
		const { alice, bob } = await makePair();
		const ciphertext = await alice.encrypt(new Uint8Array(0));
		expect(await bob.decrypt(ciphertext)).toEqual(new Uint8Array(0));
	});
});
