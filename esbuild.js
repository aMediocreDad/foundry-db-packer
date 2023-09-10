import nodeBuiltins from "builtin-modules";
import { build } from "esbuild";

build({
	banner: {
		js: "import { createRequire as yix6bKft } from 'module';const require = yix6bKft(import.meta.url);",
	},
	entryPoints: ["src/index.ts"],
	bundle: true,
	outfile: "dist/index.js",
	platform: "node",
	target: "node20",
	external: ["node:path", "node:fs", "node:fs/promises", "classic-level", ...nodeBuiltins],
	format: "iife",
	logLevel: "info",
}).catch(() => process.exit(1));
