import { setFailed, getInput, getBooleanInput } from "@actions/core";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { createDB } from "./utils.js";

try {
	const inputDirInput = getInput("inputdir") || "packs";
	const inputdir = resolve(process.cwd(), inputDirInput);

	const packsInput = getInput("packsdir");
	if (!packsInput) throw new Error("No packs directory specified");

	const packsdir = resolve(process.cwd(), packsInput || "packs");

	if (!existsSync(inputdir)) throw new Error(`Input directory ${inputdir} does not exist`);
	if (!existsSync(packsdir)) throw new Error(`Packs directory ${packsdir} does not exist`);

	const packNeDB = getBooleanInput("pack_nedb");
	const packClassicLevel = getBooleanInput("pack_classiclevel");

	await createDB({
		inputdir,
		packsdir,
		packNeDB,
		packClassicLevel,
	});
} catch (error) {
	if (error instanceof Error) setFailed(error.message);
	else setFailed("Unknown error");
	process.exit(1);
}
