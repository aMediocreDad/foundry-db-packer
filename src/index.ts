import { getBooleanInput, getInput, setFailed } from "@actions/core";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { ensureFVTTCli, remove } from "./utils.js";

try {
	const inputDirInput = getInput("inputdir");
	if (!inputDirInput) throw new Error("No packs directory specified");

	const inputdir = resolve(process.cwd(), inputDirInput);
	if (!existsSync(inputdir)) throw new Error(`Input directory ${inputdir} does not exist`);

	const packsInput = getInput("packsdir") || "packs";
	const packsdir = resolve(process.cwd(), packsInput);
	if (!existsSync(packsdir)) throw new Error(`Packs directory ${packsdir} does not exist`);

	const fvttCliPath = await ensureFVTTCli();

	const { compilePack } = await import(`${fvttCliPath}/index.mjs`).catch((err) => {
		const detail = err instanceof Error ? err.message : String(err);
		throw new Error(
			`Failed to load foundryvtt-cli from ${fvttCliPath}. This usually means classic-level's ` +
				`prebuilt binary does not match this runner (node ${process.version}, ` +
				`${process.platform}-${process.arch}). Original error: ${detail}`,
		);
	});

	await compilePack(inputdir, packsdir, {
		log: true,
		recursive: true,
	});

	if (getBooleanInput("remove_input")) await remove(inputdir);
} catch (error) {
	if (error instanceof Error) setFailed(error.message);
	else setFailed("Unknown error");
	process.exit(1);
}
