import { getBooleanInput, getInput, setFailed } from "@actions/core";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { createDB, ensureClassicLevel } from "./utils.js";

async function main() {
	try {
		const inputDirInput = getInput("inputdir");
		const inputdir = resolve(process.cwd(), inputDirInput);
		if (!inputDirInput) throw new Error("No packs directory specified");

		const packsInput = getInput("packsdir") || "packs";

		const packsdir = resolve(process.cwd(), packsInput);

		if (!existsSync(inputdir)) throw new Error(`Input directory ${inputdir} does not exist`);
		if (!existsSync(packsdir)) throw new Error(`Packs directory ${packsdir} does not exist`);

		const packNeDB = getBooleanInput("pack_nedb");
		const packClassicLevel = getBooleanInput("pack_classiclevel");

		if (packClassicLevel) await ensureClassicLevel();

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
}

main();
