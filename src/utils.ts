import { info } from "@actions/core";
import { exec } from "@actions/exec";
import { statSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { Package } from "@foundryvtt/foundryvtt-cli";

export async function ensureClassicLevel() {
	const isInstalled = await exec("npm", ["ls", "-g", "classic-level"])
		.then(() => true)
		.catch(() => false);
	if (isInstalled) return;

	console.log("Installing classic-level");

	await exec("npm", ["install", "-g", "classic-level"]).catch((err) => {
		console.error("Error installing classic-level");
		throw err;
	});
}

export async function createDB({
	inputdir,
	packsdir,
	packNeDB,
	packClassicLevel,
}: {
	inputdir: string;
	packsdir: string;
	packNeDB: boolean;
	packClassicLevel: boolean;
}) {
	return readdir(inputdir)
		.then(async (dir) => {
			for (const subdir of dir) {
				if (statSync(`${inputdir}/${subdir}`).isDirectory()) {
					if (packClassicLevel)
						await Package.packClassicLevel(`${packsdir}/${subdir}`, `${inputdir}/${subdir}`)
							.then(() => {
								info(`Packed ${subdir} as a classic LevelDB`);
							})
							.catch((err) => {
								console.error(`Error packing ${subdir} as a classic LevelDB`);
								throw err;
							});
					if (packNeDB)
						await Package.packNedb(packsdir, `${inputdir}/${subdir}`, subdir)
							.then(() => {
								info(`Packed ${subdir} as a NeDB`);
							})
							.catch((err) => {
								console.error(`Error packing ${subdir} as a NeDB`);
								throw err;
							});
				}
			}
		})
		.catch((err) => {
			console.error("Error reading input directory");
			throw err;
		});
}
