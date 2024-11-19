import path from "node:path";
import { error, info } from "@actions/core";
import { exec, getExecOutput } from "@actions/exec";
// @ts-expect-error - No types available
import { compilePack } from "@foundryvtt/foundryvtt-cli";


export function normalizePath(pathToNormalize: string): string {
	return path.normalize(pathToNormalize).split(path.sep).join(path.posix.sep);
}

export async function ensureClassicLevel(tried = false): Promise<string> {
	const installedPath = await getExecOutput("npm", ["ls", "-g", "--parseable", "@foundryvtt/foundryvtt-cli"], {
		silent: true,
	})
		.then((out) => {
			if (out.exitCode !== 0) return "";
			if (out.stdout.trim() === "") return "";
			info(`Found foundryvtt-cli package: ${out.stdout}`);
			return out.stdout.trim();
		})
		.catch(() => "");
	if (installedPath) return installedPath;
	if (tried) throw new Error("Failed to install foundryvtt-cli");

	info("Installing foundryvtt-cli");
	await exec("npm", ["install", "-g", "@foundryvtt/foundryvtt-cli"]).catch((err) => {
		error("Error installing foundryvtt-cli");
		throw err;
	});

	return ensureClassicLevel(true);
}

export async function remove(inputdir: string): Promise<void> {
	await exec("rm", ["-rf", inputdir]);
}