import { exec } from "@actions/exec";
import { existsSync } from "node:fs";
import { rm } from "node:fs/promises";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
// @ts-expect-error - No types available
import { compilePack } from "@foundryvtt/foundryvtt-cli";

import * as utils from "../src/utils.js";

const jsonDir = new URL("../__fixtures__/dummy-json", import.meta.url).pathname;
const moduleDir = new URL("../__fixtures__/test-module/packs/test", import.meta.url).pathname;

afterAll(async () => {
	if (existsSync(`${moduleDir}`)) await rm(`${moduleDir}`, { recursive: true });
});

describe("Utils:ensureClassicLevel", () => {
	it("should ensure classic-level is installed", async () => {
		await utils.ensureClassicLevel();
		expect(await exec("npm", ["ls", "-g", "@foundryvtt/foundryvtt-cli"])).toBe(0);
	});
});

describe("Package", () => {
	beforeEach(async () => {
		if (existsSync(`${moduleDir}`)) await rm(`${moduleDir}`, { recursive: true });
	});

	it("should produce a valid Classic levelDB structure", async () => {
		await compilePack(
			jsonDir,
			moduleDir, {
			log: true,
			recursive: true,
		});
		expect(existsSync(`${moduleDir}/LOCK`)).toBe(true);
	});
});