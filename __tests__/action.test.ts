import { existsSync } from "node:fs";
import { rm } from "node:fs/promises";
import { afterAll, beforeEach, describe, expect, it } from "vitest";

import * as utils from "../src/utils.js";

const jsonDir = new URL("../__fixtures__/dummy-json", import.meta.url).pathname;
const moduleDir = new URL("../__fixtures__/test-module/packs", import.meta.url).pathname;

afterAll(async () => {
	if (existsSync(`${moduleDir}/test`)) await rm(`${moduleDir}/test`, { recursive: true });
	if (existsSync(`${moduleDir}/test.db`)) await rm(`${moduleDir}/test.db`);
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
