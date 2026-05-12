import { rm } from "node:fs/promises";
import { error, info } from "@actions/core";
import { exec, getExecOutput } from "@actions/exec";

const FVTT_CLI_VERSION = "3.0.3";

export async function ensureFVTTCli(tried = false): Promise<string> {
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
	if (tried) throw new Error("Failed to install @foundryvtt/foundryvtt-cli");

	info(`Installing @foundryvtt/foundryvtt-cli@${FVTT_CLI_VERSION}`);
	await exec("npm", ["install", "-g", `@foundryvtt/foundryvtt-cli@${FVTT_CLI_VERSION}`]).catch((err) => {
		error("Error installing @foundryvtt/foundryvtt-cli");
		throw err;
	});

	return ensureFVTTCli(true);
}

export async function remove(inputdir: string): Promise<void> {
	await rm(inputdir, { recursive: true, force: true });
}
