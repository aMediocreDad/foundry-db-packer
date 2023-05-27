import { error, info } from "@actions/core";
import { statSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { Package } from "@foundryvtt/foundryvtt-cli";

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
