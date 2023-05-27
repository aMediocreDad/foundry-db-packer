import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { Package } from "@foundryvtt/foundryvtt-cli";
import { readFile, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { exec } from "@actions/exec";

import * as utils from "../src/utils.js";

const jsonDir = new URL("../__fixtures__/dummy-json", import.meta.url).pathname;
const moduleDir = new URL("../__fixtures__/test-module/packs", import.meta.url).pathname;

afterAll(async () => {
	if (existsSync(`${moduleDir}/test`)) await rm(`${moduleDir}/test`, { recursive: true });
	if (existsSync(`${moduleDir}/test.db`)) await rm(`${moduleDir}/test.db`);
});

describe("@FoundryVTT/fvtt-cli:Package", () => {
	beforeEach(async () => {
		if (existsSync(`${moduleDir}/test`)) await rm(`${moduleDir}/test`, { recursive: true });
		if (existsSync(`${moduleDir}/test.db`)) await rm(`${moduleDir}/test.db`);
	});

	it("should produce a valid Classic levelDB structure", async () => {
		await Package.packClassicLevel(moduleDir + "/test", jsonDir + "/test");
		expect(existsSync(`${moduleDir}/test/LOCK`)).toBe(true);
	});

	it("should produce a valid nedb database file", async () => {
		await Package.packNedb(moduleDir, jsonDir + "/test", "test");
		expect(existsSync(`${moduleDir}/test.db`)).toBe(true);

		const dbFile = await readFile(`${moduleDir}/test.db`, "utf8");
		expect(dbFile).toMatch(/_id":"JZbNhxKEWMarDvp9"/);
	});
});

describe("Utils:ensureClassicLevel", () => {
	it("should install classic-level", async () => {
		await utils.ensureClassicLevel();
		expect(await exec("npm", ["ls", "classic-level"])).toBe(0);
	});
});

describe("Utils:createDB", () => {
	beforeEach(async () => {
		if (existsSync(`${moduleDir}/test`)) await rm(`${moduleDir}/test`, { recursive: true });
		if (existsSync(`${moduleDir}/test.db`)) await rm(`${moduleDir}/test.db`);
	});

	it("should pack a directory of JSON files into a Classic LevelDB", async () => {
		await utils.createDB({
			inputdir: jsonDir,
			packsdir: moduleDir,
			packNeDB: false,
			packClassicLevel: true,
		});
		debugger;
		expect(existsSync(`${moduleDir}/test/LOCK`)).toBe(true);
	});

	it("should pack a directory of JSON files into a NeDB", async () => {
		await utils.createDB({
			inputdir: jsonDir,
			packsdir: moduleDir,
			packNeDB: true,
			packClassicLevel: false,
		});
		expect(existsSync(`${moduleDir}/test.db`)).toBe(true);
	});
});
