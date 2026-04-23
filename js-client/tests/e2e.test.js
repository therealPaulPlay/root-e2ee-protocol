import { describe, test, expect, afterEach } from "vitest";
import { spawn } from "node:child_process";
import { connect } from "node:net";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "../src/client.js";
import { generateKeypair } from "../src/crypto.js";

const SERVER_PKG = fileURLToPath(new URL("../../go-server/cmd/test_server", import.meta.url));

/**
 * @param {{ dropAck?: boolean, keyMaxAgeMs?: number, requestTimeoutMs?: number }} [opts]
 */
async function spawnHarness({ dropAck = false, keyMaxAgeMs, requestTimeoutMs } = {}) {
	const serverKeypair = await rawKeypair();
	const clientKeypair = await generateKeypair();

	const socketDir = await mkdtemp(join(tmpdir(), "e2ee-"));
	const socketPath = join(socketDir, "s.sock");

	const args = [
		"run", ".",
		"-socket", socketPath,
		"-self-id", "server-1",
		"-private-key", toHex(serverKeypair.privateKey),
		"-client-id", "client-1",
		"-client-pub", toHex(clientKeypair.publicKey),
		...(dropAck ? ["-drop-ack"] : [])
	];
	const proc = spawn("go", args, { cwd: SERVER_PKG, stdio: ["ignore", "pipe", "pipe"] });
	proc.stderr.on("data", (d) => process.stderr.write(d));
	await waitForReady(proc);

	const sock = connect(socketPath);
	await new Promise((resolve, reject) => {
		sock.once("connect", resolve);
		sock.once("error", reject);
	});

	/**
	 * @typedef {{ privateKey: Uint8Array, serverPublicKey: Uint8Array, createdAt: number }} CurrentKeys
	 * @typedef {{ privateKey: Uint8Array, serverPublicKey: Uint8Array }} PreviousKeys
	 */
	/** @type {{ current: CurrentKeys, previous: PreviousKeys | null }} */
	const keyState = {
		current: {
			privateKey: clientKeypair.privateKey,
			serverPublicKey: serverKeypair.publicKey,
			createdAt: Date.now()
		},
		previous: null
	};
	const keyStore = {
		async getCurrent() { return keyState.current; },
		async getPrevious() { return keyState.previous; },
		/**
		 * @param {string} _id
		 * @param {Uint8Array} newPriv
		 */
		async commitNewKey(_id, newPriv) {
			keyState.previous = { privateKey: keyState.current.privateKey, serverPublicKey: keyState.current.serverPublicKey };
			keyState.current = { privateKey: newPriv, serverPublicKey: keyState.current.serverPublicKey, createdAt: Date.now() };
		},
		async revertToPrevious() {
			if (!keyState.previous) return;
			keyState.current = { ...keyState.previous, createdAt: Date.now() };
			keyState.previous = null;
		}
	};

	const client = new Client({ selfId: "client-1", keyStore, keyMaxAgeMs, requestTimeoutMs });
	/** @param {Uint8Array} bytes */
	const write = (bytes) => writeFrame(sock, bytes);
	readFrames(sock, (/** @type {Uint8Array} */ bytes) => client.receive(bytes));

	return {
		client,
		write,
		keyState,
		async teardown() {
			sock.destroy();
			proc.kill("SIGTERM");
			await new Promise((resolve) => proc.once("exit", resolve));
		}
	};
}

/** @param {Uint8Array} bytes */
function toHex(bytes) {
	return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Generate a raw-scalar P-256 keypair for the server (Go uses raw, not PKCS8)
async function rawKeypair() {
	const pair = /** @type {CryptoKeyPair} */ (await crypto.subtle.generateKey(
		{ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]
	));
	const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
	const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
	const privateKey = b64urlToBytes(/** @type {string} */ (jwk.d));
	return { publicKey, privateKey };
}

/** @param {string} s */
function b64urlToBytes(s) {
	const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
	const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
	const binary = atob(b64);
	return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/**
 * @param {import("node:child_process").ChildProcessByStdio<null, import("node:stream").Readable, import("node:stream").Readable>} proc
 * @param {number} [timeoutMs]
 */
async function waitForReady(proc, timeoutMs = 10000) {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error("server did not become READY in time")), timeoutMs);
		let buf = "";
		/** @param {Buffer} chunk */
		const onData = (chunk) => {
			buf += chunk.toString();
			if (buf.includes("READY")) {
				clearTimeout(timer);
				proc.stdout.off("data", onData);
				resolve(undefined);
			}
		};
		proc.stdout.on("data", onData);
		proc.once("exit", (/** @type {number | null} */ code) => {
			clearTimeout(timer);
			reject(new Error(`server exited before READY (code=${code})`));
		});
	});
}

/**
 * @param {import("node:net").Socket} sock
 * @param {Uint8Array} bytes
 */
function writeFrame(sock, bytes) {
	const len = Buffer.alloc(4);
	len.writeUInt32BE(bytes.length, 0);
	sock.write(len);
	sock.write(Buffer.from(bytes));
}

/**
 * @param {import("node:net").Socket} sock
 * @param {(bytes: Uint8Array) => void} onFrame
 */
function readFrames(sock, onFrame) {
	let buf = Buffer.alloc(0);
	sock.on("data", (/** @type {Buffer} */ chunk) => {
		buf = Buffer.concat([buf, chunk]);
		while (buf.length >= 4) {
			const len = buf.readUInt32BE(0);
			if (buf.length < 4 + len) break;
			onFrame(new Uint8Array(buf.subarray(4, 4 + len)));
			buf = buf.subarray(4 + len);
		}
	});
}

describe("e2e cross-language", () => {
	/** @type {Awaited<ReturnType<typeof spawnHarness>> | null} */
	let h;
	afterEach(async () => { if (h) { await h.teardown(); h = null; } });

	test("roundtrips an echo request", async () => {
		h = await spawnHarness();
		const reply = await h.client.request("server-1", "echo", { hello: "world" }, h.write);
		expect(reply).toEqual({ hello: "world" });
	});

	test("roundtrips an add request with structured CBOR", async () => {
		h = await spawnHarness();
		const reply = await h.client.request("server-1", "add", { a: 3, b: 4 }, h.write);
		expect(reply).toEqual({ sum: 7 });
	});

	test("throws RelayError(UNKNOWN_TYPE) for unregistered request types", async () => {
		h = await spawnHarness();
		await expect(h.client.request("server-1", "non-existant", {}, h.write))
			.rejects.toMatchObject({ name: "RelayError", code: "UNKNOWN_TYPE" });
	});

	test("delivers a server push via onPush", async () => {
		h = await spawnHarness();
		/** @type {any[]} */
		const pushes = [];
		h.client.onPush("server-1", "tick", (payload) => { pushes.push(payload); });
		const reply = await h.client.request("server-1", "trigger-push", {}, h.write);
		expect(reply).toEqual({ ok: true });
		expect(pushes).toEqual([{ n: 42 }]);
	});

	test("renews the key and keeps working through multiple renewals", async () => {
		// keyMaxAgeMs: 0 forces a renewal before every request
		h = await spawnHarness({ keyMaxAgeMs: 0 });
		const originalPriv = h.keyState.current.privateKey;

		const r1 = await h.client.request("server-1", "echo", { n: 1 }, h.write);
		expect(r1).toEqual({ n: 1 });
		expect(h.keyState.current.privateKey).not.toEqual(originalPriv);
		const afterFirst = h.keyState.current.privateKey;

		const r2 = await h.client.request("server-1", "echo", { n: 2 }, h.write);
		expect(r2).toEqual({ n: 2 });
		expect(h.keyState.current.privateKey).not.toEqual(afterFirst);

		const r3 = await h.client.request("server-1", "echo", { n: 3 }, h.write);
		expect(r3).toEqual({ n: 3 });
	});

	test("recovers from a lost renewKeyAck by reverting to the previous key", async () => {
		// Short requestTimeoutMs so the internal ACK wait gives up quickly
		h = await spawnHarness({ dropAck: true, keyMaxAgeMs: 0, requestTimeoutMs: 1500 });
		const originalPriv = h.keyState.current.privateKey;

		// First request triggers a renewal -> server drops renewKeyAckResult -> from the server's
		// pov the key was never committed -> next real request encrypts with the new key ->
		// server can't decrypt -> returns DECRYPTION_FAILED -> client reverts to previous and retries
		const reply = await h.client.request("server-1", "echo", { hi: true }, h.write);
		expect(reply).toEqual({ hi: true });
		expect(h.keyState.current.privateKey).toEqual(originalPriv);
		expect(h.keyState.previous).toBeNull();
	});

	test("decrypts in-flight server pushes encrypted with the previous session, then keeps using the new session for subsequent traffic", async () => {
		h = await spawnHarness({ keyMaxAgeMs: 0 });
		/** @type {any[]} */
		const pushes = [];
		/** @type {((v: any) => void)|null} */
		let resolveStale = null;
		const staleReceived = new Promise((r) => { resolveStale = r; });
		h.client.onPush("server-1", "stale-tick", (payload) => {
			pushes.push(payload);
			if (resolveStale) resolveStale(null);
			return undefined;
		});

		// Force a renewal (server auto-stashes the pre-rotation client pub in CommitClientPublicKey)
		await h.client.request("server-1", "echo", { n: 1 }, h.write);
		// Server pushes a message encrypted under the stashed (now-previous) session
		// The client's current session can't decrypt it, so the previous-session fallback must kick in
		await h.client.request("server-1", "push-under-stashed", {}, h.write);
		await staleReceived;
		expect(pushes).toEqual([{ stale: true }]);

		// Subsequent traffic must continue using the new session (not get stuck on the previous one)
		const followUp = await h.client.request("server-1", "echo", { after: true }, h.write);
		expect(followUp).toEqual({ after: true });
	});

	test("rejects requests with reserved message types", async () => {
		h = await spawnHarness();
		await expect(h.client.request("server-1", "renewKey", {}, h.write)).rejects.toThrow(/Reserved/);
		await expect(h.client.request("server-1", "renewKeyAck", {}, h.write)).rejects.toThrow(/Reserved/);
	});

	test("surfaces a replayed request envelope as a REPLAY error on a matching push handler", async () => {
		const harness = await spawnHarness();
		h = harness;

		/** @type {Uint8Array | null} */
		let captured = null;
		const capturingWrite = (/** @type {Uint8Array} */ bytes) => {
			if (captured === null) captured = bytes;
			harness.write(bytes);
		};

		const first = await harness.client.request("server-1", "echo", { once: true }, capturingWrite);
		expect(first).toEqual({ once: true });

		// Replayed envelope's requestId no longer matches a pending request, so it routes
		// to push handlers; the server-emitted REPLAY arrives as an error on the "echo" type
		/** @type {(error: string) => void} */
		let resolveError = () => { };
		const errorReceived = new Promise((/** @type {(value: string) => void} */ resolve) => { resolveError = resolve; });
		harness.client.onPush("server-1", "echo", (_payload, error) => {
			if (error) resolveError(error.code);
		});

		if (!captured) throw new Error("write was not captured");
		harness.write(captured);

		expect(await errorReceived).toBe("REPLAY");
	});
});