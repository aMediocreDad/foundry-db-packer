import { createDB, ensureClassicLevel } from "./src/utils.js";

await ensureClassicLevel();

createDB({
	inputdir: "./data",
	packsdir: "./data",
	packClassicLevel: true,
	packNeDB: true,
});
