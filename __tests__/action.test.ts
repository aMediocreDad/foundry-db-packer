import { exec } from "@actions/exec";
import { existsSync } from "node:fs";
import { readFile, rm } from "node:fs/promises";
import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { Package } from "../src/package.js";
import * as utils from "../src/utils.js";

const jsonDir = new URL("../__fixtures__/dummy-json", import.meta.url).pathname;
const moduleDir = new URL("../__fixtures__/test-module/packs", import.meta.url).pathname;

afterAll(async () => {
	if (existsSync(`${moduleDir}/test`)) await rm(`${moduleDir}/test`, { recursive: true });
	if (existsSync(`${moduleDir}/test.db`)) await rm(`${moduleDir}/test.db`);
});

describe("Package", () => {
	beforeEach(async () => {
		if (existsSync(`${moduleDir}/test`)) await rm(`${moduleDir}/test`, { recursive: true });
		if (existsSync(`${moduleDir}/test.db`)) await rm(`${moduleDir}/test.db`);
	});

	it("should produce a valid Classic levelDB structure", async () => {
		const module = await import((await utils.ensureClassicLevel()) + "/index.js");
		const ClassicLevel = module.ClassicLevel;
		await Package.packClassicLevel(moduleDir + "/test", jsonDir + "/test", ClassicLevel);
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
	it("should ensure classic-level is installed", async () => {
		await utils.ensureClassicLevel();
		expect(await exec("npm", ["ls", "-g", "classic-level"])).toBe(0);
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
			ClassicLevel: (await import((await utils.ensureClassicLevel()) + "/index.js")).ClassicLevel,
		});
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
