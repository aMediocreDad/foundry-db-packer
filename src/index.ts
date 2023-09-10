import { getBooleanInput, getInput, setFailed } from "@actions/core";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { createDB, ensureClassicLevel } from "./utils.js";

try {
	const inputDirInput = getInput("inputdir");
	if (!inputDirInput) throw new Error("No packs directory specified");

	const inputdir = resolve(process.cwd(), inputDirInput);
	if (!existsSync(inputdir)) throw new Error(`Input directory ${inputdir} does not exist`);

	const packsInput = getInput("packsdir") || "packs";
	const packsdir = resolve(process.cwd(), packsInput);
	if (!existsSync(packsdir)) throw new Error(`Packs directory ${packsdir} does not exist`);

	const packNeDB = getBooleanInput("pack_nedb");
	const packClassicLevel = getBooleanInput("pack_classiclevel");

	let ClassicLevel: typeof import("classic-level").ClassicLevel | undefined;
	if (packClassicLevel) {
		const classicLevelPath = await ensureClassicLevel();
		const module = await import(classicLevelPath + "/index.js");
		ClassicLevel = module.ClassicLevel;
	}

	await createDB({
		inputdir,
		packsdir,
		packNeDB,
		packClassicLevel,
		ClassicLevel,
	});
} catch (error) {
	if (error instanceof Error) setFailed(error.message);
	else setFailed("Unknown error");
	process.exit(1);
}
