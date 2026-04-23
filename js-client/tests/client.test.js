import { describe, test, expect } from "vitest";
import { Encoder } from "cbor-x";
import { Client } from "../src/client.js";

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
});
