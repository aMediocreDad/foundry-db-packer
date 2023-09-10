import { error, info } from "@actions/core";
import { exec, getExecOutput } from "@actions/exec";
import { statSync } from "node:fs";
import { readdir } from "node:fs/promises";

import { Package } from "./package.js";

export async function ensureClassicLevel(tried = false): Promise<string> {
	const installedPath = await getExecOutput("npm", ["ls", "-g", "--parseable", "classic-level"], {
		silent: true,
	})
		.then((out) => {
			if (out.exitCode !== 0) return "";
			if (out.stdout.trim() === "") return "";
			info(`Found classic-level: ${out.stdout}`);
			return out.stdout.trim();
		})
		.catch(() => "");
	if (installedPath) return installedPath;
	if (tried) throw new Error("Failed to install classic-level");

	info("Installing classic-level");
	await exec("npm", ["install", "-g", "classic-level@1.3.0"]).catch((err) => {
		error("Error installing classic-level");
		throw err;
	});

	return ensureClassicLevel(true);
}

export async function createDB({
	inputdir,
	packsdir,
	packNeDB,
	packClassicLevel,
	ClassicLevel,
}: {
	inputdir: string;
	packsdir: string;
	packNeDB: boolean;
	packClassicLevel: boolean;
	ClassicLevel?: typeof import("classic-level").ClassicLevel;
}) {
	return readdir(inputdir)
		.then(async (dir) => {
			for (const subdir of dir) {
				if (statSync(`${inputdir}/${subdir}`).isDirectory()) {
					if (packClassicLevel)
						await Package.packClassicLevel(`${packsdir}/${subdir}`, `${inputdir}/${subdir}`, ClassicLevel!)
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
