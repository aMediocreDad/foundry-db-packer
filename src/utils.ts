import { error, info } from "@actions/core";
import { exec, getExecOutput } from "@actions/exec";
import { statSync } from "node:fs";
import { readdir } from "node:fs/promises";

export async function ensureClassicLevel(tries = 1) {
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

	if (tries > 3) throw new Error("Failed to install classic-level");

	info("Attempting to install classic-level");
	if (tries > 1) info(`Attempt number ${tries}`);
	await exec("npm", ["install", "classic-level"]).catch((err) => {
		error("Error installing classic-level");
		throw err;
	});
	await ensureClassicLevel(tries++);
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
	const { compilePack } = await import("@foundryvtt/foundryvtt-cli");
	return readdir(inputdir)
		.then(async (dir) => {
			for (const subdir of dir) {
				if (statSync(`${inputdir}/${subdir}`).isDirectory()) {
					if (packClassicLevel)
						await compilePack(`${inputdir}/${subdir}`, `${packsdir}/${subdir}`, {
							log: true,
							recursive: true,
						})
							.then(() => {
								info(`Packed ${subdir} as a classic LevelDB`);
							})
							.catch((err) => {
								error(`Error packing ${subdir} as a classic LevelDB`);
								throw err;
							});
					if (packNeDB)
						await compilePack(`${inputdir}/${subdir}`, `${packsdir}/${subdir}.db`, {
							log: true,
							recursive: true,
							nedb: true,
						})
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
