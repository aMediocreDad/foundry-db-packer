import { error, info } from "@actions/core";
import { exec, getExecOutput } from "@actions/exec";
import { statSync } from "node:fs";
import { readdir } from "node:fs/promises";

import { Package } from "./package.js";

export async function ensureClassicLevel() {
	const isInstalled = await getExecOutput("npm", ["ls", "classic-level"], {
		silent: true,
	})
		.then((out) => {
			if (out.exitCode !== 0) return false;
			info(`Found classic-level: ${out.stdout}`);
			return true;
		})
		.catch(() => false);
	if (isInstalled) return;

	info("Installing classic-level");
	await exec("npm", ["install", "classic-level"]).catch((err) => {
		error("Error installing classic-level");
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
								error(`Error packing ${subdir} as a classic LevelDB`);
								throw err;
							});
					if (packNeDB)
						await Package.packNedb(packsdir, `${inputdir}/${subdir}`, subdir)
							.then(() => {
								info(`Packed ${subdir} as a NeDB`);
							})
							.catch((err) => {
								error(`Error packing ${subdir} as a NeDB`);
								throw err;
							});
				}
			}
		})
		.catch((err) => {
			error("Error reading input directory");
			throw err;
		});
}
