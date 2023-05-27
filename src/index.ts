import { setFailed, getInput, getBooleanInput, info } from "@actions/core";
import { Package } from "@foundryvtt/foundryvtt-cli";
import { existsSync, statSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { resolve } from "node:path";

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

	readdir(inputdir)
		.then(async (dir) => {
			for (const subdir of dir) {
				if (statSync(`${inputdir}/${subdir}`).isDirectory()) {
					if (packClassicLevel)
						await Package.packClassicLevel(packsdir, `${inputdir}/${subdir}`).then(() => {
							info(`Packed ${subdir} as a classic LevelDB`);
						});
					if (packNeDB)
						await Package.packNedb(packsdir, `${inputdir}/${subdir}`, subdir).then(() => {
							info(`Packed ${subdir} as a NeDB`);
						});
				}
			}
		})
		.catch((err) => {
			console.error("Error reading input directory");
			throw err;
		});
} catch (error) {
	if (error instanceof Error) setFailed(error.message);
	else setFailed("Unknown error");
	process.exit(1);
}
