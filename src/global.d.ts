declare module "@foundryvtt/foundryvtt-cli" {
	async function compilePack(
		src: string,
		dest: string,
		{
			nedb = false,
			yaml = false,
			recursive = false,
			log = false,
			transformEntry,
		}: {
			nedb?: boolean;
			yaml?: boolean;
			recursive?: boolean;
			log?: boolean;
			transformEntry?: (entry: { [key: stirng]: any }) => Promise<false | void>;
		} = {}
	): Promise<void>;
}
