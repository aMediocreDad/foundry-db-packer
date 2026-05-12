import { build } from "esbuild";
import nodeBuiltins from "builtin-modules";

build({
	banner: {
		js: "import { createRequire as yix6bKft } from 'module';const require = yix6bKft(import.meta.url);",
	},
	entryPoints: ["src/index.ts"],
	bundle: true,
	outfile: "dist/index.js",
	platform: "node",
	target: "node24",
	external: [
		"node:path",
		"node:fs",
		"node:fs/promises",
		"@foundryvtt/foundryvtt-cli",
		...nodeBuiltins,
	],
	format: "esm",
	logLevel: "info",
}).catch(() => process.exit(1));
