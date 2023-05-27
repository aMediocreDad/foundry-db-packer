import { describe, it, expect, beforeAll } from "vitest";
import { Package } from "@foundryvtt/foundryvtt-cli";
import { mkdir, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";

const jsonDir = new URL("../__fixtures__/dummy-json/test", import.meta.url).pathname;
const moduleDir = new URL("../__fixtures__/test-module/packs", import.meta.url).pathname;
const packDir = new URL("../__fixtures__/dummy-module/packs/dummy", import.meta.url).pathname;
const outDir = new URL("../__test-files__", import.meta.url).pathname;

beforeAll(async () => {
	if (!existsSync(outDir)) {
		await mkdir(outDir, { recursive: true });
	}
});

describe("@FoundryVTT/fvtt-cli:Package", () => {
	it("should unpack a Classic LevelDB as JSON", async () => {
		await Package.unpackClassicLevel(packDir, outDir);
		expect(existsSync(`${outDir}/test_2_yeEHA8lgkCbNr4V7.json`)).toBe(true);

		const { default: json } = await import(`${outDir}/test4_f6ViPysunpvdWxq9.json`);
		expect(json).toHaveProperty("name", "Test4");
		expect(json).toHaveProperty("_key", "!items!f6ViPysunpvdWxq9");
	});
	it("should produce a valid Classic levelDB structure", async () => {
		await Package.packClassicLevel(moduleDir + "/test", jsonDir);
		expect(existsSync(`${moduleDir}/test/LOCK`)).toBe(true);
	});
	it("should produce a valid nedb database file", async () => {
		await Package.packNedb(moduleDir, jsonDir, "test");
		expect(existsSync(`${moduleDir}/test.db`)).toBe(true);

		const dbFile = await readFile(`${moduleDir}/test.db`, "utf8");
		expect(dbFile).toMatch(/_id":"JZbNhxKEWMarDvp9"/);
	});
});
