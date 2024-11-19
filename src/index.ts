import { getBooleanInput, getInput, setFailed } from "@actions/core";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { ensureClassicLevel, remove } from "./utils.js";

try {
	const inputDirInput = getInput("inputdir");
	if (!inputDirInput) throw new Error("No packs directory specified");

	const inputdir = resolve(process.cwd(), inputDirInput);
	if (!existsSync(inputdir)) throw new Error(`Input directory ${inputdir} does not exist`);

	const packsInput = getInput("packsdir") || "packs";
	const packsdir = resolve(process.cwd(), packsInput);
	if (!existsSync(packsdir)) throw new Error(`Packs directory ${packsdir} does not exist`);

	const remove_input = getBooleanInput("remove_input");

	const path = await ensureClassicLevel();

	const { compilePack } = await import(`${path}/index.mjs`);

	await compilePack(
		inputdir,
		packsdir, {
		log: true,
		recursive: true,
	});

	if (remove_input) await remove(`${inputdir}/_source`);
} catch (error) {
	if (error instanceof Error) setFailed(error.message);
	else setFailed("Unknown error");
	process.exit(1);
}
