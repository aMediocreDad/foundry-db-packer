import { error, info } from "@actions/core";
import { statSync } from "node:fs";
import { readdir } from "node:fs/promises";

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
