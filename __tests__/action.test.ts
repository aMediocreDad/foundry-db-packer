import { exec } from "@actions/exec";
import { existsSync } from "node:fs";
import { readdir, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error - No types available
import { compilePack, extractPack } from "@foundryvtt/foundryvtt-cli";

import * as utils from "../src/utils.js";

const jsonDir = new URL("../__fixtures__/dummy-json", import.meta.url).pathname;
const moduleDir = new URL("../__fixtures__/test-module/packs/test", import.meta.url).pathname;
const extractDir = new URL("../__fixtures__/test-module/packs/test-extracted", import.meta.url).pathname;

afterAll(async () => {
	if (existsSync(moduleDir)) await rm(moduleDir, { recursive: true });
	if (existsSync(extractDir)) await rm(extractDir, { recursive: true });
});

describe("Utils:ensureFVTTCli", () => {
	it("should ensure @foundryvtt/foundryvtt-cli is installed", async () => {
		await utils.ensureFVTTCli();
		expect(await exec("npm", ["ls", "-g", "@foundryvtt/foundryvtt-cli"])).toBe(0);
	});
});

describe("Package", () => {
	beforeEach(async () => {
		if (existsSync(moduleDir)) await rm(moduleDir, { recursive: true });
		if (existsSync(extractDir)) await rm(extractDir, { recursive: true });
	});

	it("should produce a valid Classic levelDB structure", async () => {
		await compilePack(jsonDir, moduleDir, {
			log: false,
			recursive: true,
		});
		expect(existsSync(`${moduleDir}/LOCK`)).toBe(true);
	});

	// Regression: https://github.com/aMediocreDad/foundry-db-packer/issues/11
	// The previously bundled compilePack predated the HIERARCHY/applyHierarchy logic
	// in @foundryvtt/foundryvtt-cli, so embedded ActiveEffects on items were silently
	// dropped: the standalone `!items.effects!{itemId}.{effectId}` entry was never
	// written to the LevelDB. Round-tripping via extractPack proves the effect entry
	// exists in the produced pack — extract fails or yields empty `effects` otherwise.
	it("preserves embedded ActiveEffects on items", async () => {
		await compilePack(jsonDir, moduleDir, {
			log: false,
			recursive: true,
		});

		await extractPack(moduleDir, extractDir, {
			log: false,
			documentType: "Item",
		});

		const files = await readdir(extractDir);
		const itemFile = files.find((f) => f.includes("aEFFECT0000Item01"));
		expect(itemFile, "extracted item file with embedded effect should exist").toBeTruthy();

		const item = JSON.parse(await readFile(path.join(extractDir, itemFile!), "utf8"));
		expect(item.effects).toHaveLength(1);
		expect(item.effects[0]._id).toBe("eEFFECT00000001");
		expect(item.effects[0].name).toBe("Test Effect");
	});
});
