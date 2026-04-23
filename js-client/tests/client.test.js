import { describe, test, expect } from "vitest";
import { Encoder } from "cbor-x";
import { Client } from "../src/client.js";
import { generateKeypair, deriveSession, computeAAD } from "../src/crypto.js";

/** @type {import("cbor-x").Options & { int64AsNumber?: boolean }} */
const cborOptions = { useRecords: false, mapsAsObjects: true, int64AsNumber: true };
const cbor = new Encoder(cborOptions);

function makeClient() {
	return new Client({
		selfId: "c",
		keyStore: {
			async getCurrent() { return null; },
			async getPrevious() { return null; },
			async commitNewKey() { },
			async revertToPrevious() { }
		}
	});
}

// A server-emitted plaintext-error envelope is delivered to onPush handlers as the error arg
function errorEnvelope() {
	return cbor.encode({
		type: "tick",
		originId: "s",
		targetId: "c",
		requestId: "",
		error: "TEST_ERROR"
	});
}

describe("Client push handlers", () => {
	test("fire in registration order with the error arg set on protocol errors", async () => {
		const client = makeClient();
		/** @type {string[]} */
		const calls = [];
		/** @type {(string | null)[]} */
		const codes = [];
		const record = (/** @type {string} */ name) => (/** @type {any} */ _payload, /** @type {{ code: string } | null} */ error) => {
			calls.push(name);
			codes.push(error?.code ?? null);
		};
		client.onPush("s", "tick", record("a"));
		client.onPush("s", "tick", record("b"));
		client.onPush("s", "tick", record("c"));

		await client.receive(errorEnvelope());
		expect(calls).toEqual(["a", "b", "c"]);
		expect(codes).toEqual(["TEST_ERROR", "TEST_ERROR", "TEST_ERROR"]);
	});

	test("offPush removes only the targeted handler", async () => {
		const client = makeClient();
		/** @type {string[]} */
		const calls = [];
		const a = () => { calls.push("a"); };
		const b = () => { calls.push("b"); };
		const c = () => { calls.push("c"); };
		client.onPush("s", "tick", a);
		client.onPush("s", "tick", b);
		client.onPush("s", "tick", c);
		client.offPush("s", "tick", b);

		await client.receive(errorEnvelope());
		expect(calls).toEqual(["a", "c"]);
	});

	test("dispatch is scoped by serverId", async () => {
		const client = makeClient();
		/** @type {string[]} */
		const calls = [];
		client.onPush("s", "tick", () => { calls.push("matched"); });
		client.onPush("other-server", "tick", () => { calls.push("wrong-server"); });

		await client.receive(errorEnvelope());
		expect(calls).toEqual(["matched"]);
	});

	test("dispatch is scoped by type", async () => {
		const client = makeClient();
		/** @type {string[]} */
		const calls = [];
		client.onPush("s", "tick", () => { calls.push("matched"); });
		client.onPush("s", "tock", () => { calls.push("wrong-type"); });

		await client.receive(errorEnvelope());
		expect(calls).toEqual(["matched"]);
	});

	test("close drops registered handlers", async () => {
		const client = makeClient();
		/** @type {string[]} */
		const calls = [];
		client.onPush("s", "tick", () => { calls.push("fired"); });

		client.close();

		await expect(client.receive(errorEnvelope())).rejects.toThrow(/Client closed/);
		expect(calls).toEqual([]);
	});

	test("request, receive, onPush, and offPush throw after close", async () => {
		const client = makeClient();
		client.close();

		await expect(client.request("s", "t", {}, () => { })).rejects.toThrow(/Client closed/);
		await expect(client.receive(errorEnvelope())).rejects.toThrow(/Client closed/);
		expect(() => client.onPush("s", "tick", () => { })).toThrow(/Client closed/);
		expect(() => client.offPush("s", "tick", () => { })).toThrow(/Client closed/);
	});

	test("close is idempotent", () => {
		const client = makeClient();
		client.close();
		client.close(); // should not throw
	});

	// Re-pairing can swap the stored keys without the library's knowledge; next request
	// must re-derive the session from the new keys instead of using the cached stale one
	test("session re-derives when KeyStore keys change out-from-under it", async () => {
		const serverKeypair = await generateKeypair();
		const firstClientKeypair = await generateKeypair();
		const secondClientKeypair = await generateKeypair();

		// Mutable keystore simulating a re-pair flow
		const state = {
			privateKey: firstClientKeypair.privateKey,
			serverPublicKey: serverKeypair.publicKey
		};
		const client = new Client({
			selfId: "c",
			keyStore: {
				async getCurrent() {
					return { privateKey: state.privateKey, serverPublicKey: state.serverPublicKey, createdAt: Date.now() };
				},
				async getPrevious() { return null; },
				async commitNewKey() { },
				async revertToPrevious() { }
			}
		});

		// Simulate a server push by building an envelope encrypted under the FIRST client's session
		const firstServerSession = await deriveSession(serverKeypair.privateKey, firstClientKeypair.publicKey);
		const aad1 = await computeAAD("tick", "s", "c");
		const cipher1 = await firstServerSession.encrypt(cbor.encode({ n: 1 }), aad1);
		const env1 = cbor.encode({ type: "tick", originId: "s", targetId: "c", requestId: "", payload: cipher1 });

		/** @type {any[]} */
		const received = [];
		client.onPush("s", "tick", (payload) => { received.push(payload); });

		await client.receive(env1);
		expect(received).toEqual([{ n: 1 }]);

		// Re-pair: keystore starts returning the second client's private key
		state.privateKey = secondClientKeypair.privateKey;

		// Build a push encrypted under the SECOND client's session
		const secondServerSession = await deriveSession(serverKeypair.privateKey, secondClientKeypair.publicKey);
		const aad2 = await computeAAD("tick", "s", "c");
		const cipher2 = await secondServerSession.encrypt(cbor.encode({ n: 2 }), aad2);
		const env2 = cbor.encode({ type: "tick", originId: "s", targetId: "c", requestId: "", payload: cipher2 });

		await client.receive(env2);
		expect(received).toEqual([{ n: 1 }, { n: 2 }]);
	});
});
