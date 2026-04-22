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

// A server-emitted plaintext-error envelope routes to onError handlers
function errorEnvelope() {
	return cbor.encode({
		type: "someResult",
		originId: "s",
		targetId: "c",
		requestId: "",
		error: "TEST_ERROR"
	});
}

describe("Client error handlers", () => {
	test("fire in registration order", async () => {
		const client = makeClient();
		/** @type {string[]} */
		const calls = [];
		client.onError(() => { calls.push("a"); });
		client.onError(() => { calls.push("b"); });
		client.onError(() => { calls.push("c"); });

		await client.receive(errorEnvelope());
		expect(calls).toEqual(["a", "b", "c"]);
	});

	test("offError removes only the targeted handler", async () => {
		const client = makeClient();
		/** @type {string[]} */
		const calls = [];
		const a = () => { calls.push("a"); };
		const b = () => { calls.push("b"); };
		const c = () => { calls.push("c"); };
		client.onError(a);
		client.onError(b);
		client.onError(c);
		client.offError(b);

		await client.receive(errorEnvelope());
		expect(calls).toEqual(["a", "c"]);
	});
});