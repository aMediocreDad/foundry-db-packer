import chalk from "chalk";
import yaml from "js-yaml";
import NeDB from "nedb-promises";
import fs from "node:fs";
import path from "node:path";

interface DB<T> extends NeDB<T> {
	compactDatafile(callback: (err: Error | null) => void): void;
	stopAutocompaction(): void;
}

export class Package {
	static normalizePath(pathToNormalize: string): string {
		return path.normalize(pathToNormalize).split(path.sep).join(path.posix.sep);
	}

	static async packNedb(packDir: string, inputDir: string, compendiumName: string): Promise<void> {
		// Load the directory as a Nedb
		const db = NeDB.create(`${packDir}/${compendiumName}.db`) as DB<Record<string, any>>;

		// Iterate over all YAML files in the input directory, writing them to the db
		const files = fs.readdirSync(inputDir);
		const seenKeys = new Set();
		for (const file of files) {
			const fileContents = fs.readFileSync(path.join(inputDir, file), "utf8");
			const value = file.endsWith(".yml") ? yaml.load(fileContents) : JSON.parse(fileContents);
			const key = value._key;

			// If the key starts with !folders, we should skip packing it as nedb doesn't support folders
			if (key.startsWith("!folders")) continue;

			delete value._key;
			seenKeys.add(value._id);

			// If key already exists, update it
			const existing = await db.findOne({ _id: value._id });
			if (existing) {
				await db.update({ _id: key }, value);
				console.log(`Updated ${chalk.blue(value._id)}${chalk.blue(value.name ? ` (${value.name})` : "")}`);
			} else {
				await db.insert(value);
				console.log(`Packed ${chalk.blue(value._id)}${chalk.blue(value.name ? ` (${value.name})` : "")}`);
			}
		}

		// Remove any entries which were not updated
		const docs = await db.find({ _id: { $nin: Array.from(seenKeys) } });
		for (const doc of docs) {
			await db.remove({ _id: doc._id }, {});
			console.log(`Removed ${chalk.blue(doc._id)}${chalk.blue(doc.name ? ` (${doc.name})` : "")}`);
		}

		// Compact the database
		db.stopAutocompaction();
		await new Promise((resolve) => {
			db.compactDatafile(resolve);
		});
	}

	static async packClassicLevel(
		packDir: string,
		inputDir: string,
		ClassicLevel: typeof import("classic-level").ClassicLevel
	): Promise<void> {
		// Load the directory as a ClassicLevel db
		const db = new ClassicLevel(packDir, { keyEncoding: "utf8", valueEncoding: "json" });
		const batch = db.batch();

		// Iterate over all YAML files in the input directory, writing them to the db
		const files = fs.readdirSync(inputDir);
		const seenKeys = new Set();
		for (const file of files) {
			const fileContents = fs.readFileSync(path.join(inputDir, file), "utf8");
			const value = file.endsWith(".yml") ? yaml.load(fileContents) : JSON.parse(fileContents);
			const key = value._key;
			delete value._key;
			seenKeys.add(key);
			batch.put(key, value);
			console.log(`Packed ${chalk.blue(value._id)}${chalk.blue(value.name ? ` (${value.name})` : "")}`);
		}

		// Remove any entries in the db that are not in the input directory
		for (const key of await db.keys().all()) {
			if (!seenKeys.has(key)) {
				batch.del(key);
				console.log(`Removed ${chalk.blue(key)}`);
			}
		}
		await batch.write();
		await db.close();
	}
}
