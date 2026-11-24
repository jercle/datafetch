// The settings the collector takes from Azure App Configuration, under the
// key azureDriftChecker. One entry per setting: its key (the part after
// "azureDriftChecker."), how it is edited and what is allowed. The
// collector's own list is internal/settings/settings.go; a Go test fails
// when the two name different keys.

export const ROOT = 'azureDriftChecker';

export type FieldKind = 'text' | 'duration' | 'int' | 'bool' | 'enum' | 'list' | 'secret';

export interface FieldSpec {
	key: string;
	label: string;
	kind: FieldKind;
	/** Heading the field is shown under. */
	group: string;
	help: string;
	/** What applies when neither the dashboard nor the file sets it. */
	fallback?: string;
	min?: number;
	max?: number;
	/** Bounds of a duration, in seconds. */
	minSeconds?: number;
	maxSeconds?: number;
	options?: readonly string[];
	/** Read when the collector starts, not before each pass. */
	restart?: boolean;
}

const LEVELS = ['debug', 'info', 'warn', 'error'] as const;

// prettier-ignore
export const GENERAL_FIELDS: readonly FieldSpec[] = [
	{ key: 'interval', label: 'Time between passes', kind: 'duration', group: 'Schedule', fallback: '6h', minSeconds: 300, help: 'How often a collector running with -loop collects. Written like 6h, 90m or 1h30m; at least 5m.' },
	{ key: 'heartbeatInterval', label: 'Heartbeat', kind: 'duration', group: 'Schedule', fallback: '30s', minSeconds: 5, maxSeconds: 60, restart: true, help: 'How often the collector reports that it is alive, and looks for a "Collect now" request. Between 5s and 1m.' },
	{ key: 'concurrency.tenants', label: 'Tenants at once', kind: 'int', group: 'Performance', fallback: '2', min: 1, max: 32, help: 'How many tenants are collected side by side.' },
	{ key: 'concurrency.modules', label: 'Modules at once', kind: 'int', group: 'Performance', fallback: '3', min: 1, max: 32, help: 'How many modules are collected side by side within a tenant. Lower it if Microsoft Graph throttles.' },
	{ key: 'limits.sourceTimeout', label: 'Longest time for one source', kind: 'duration', group: 'Performance', fallback: '2h', minSeconds: 60, help: 'A source that takes longer in one tenant is stopped and recorded as failed.' },
	{ key: 'limits.maxItemBytes', label: 'Largest settings stored per object', kind: 'int', group: 'Performance', fallback: '4194304', min: 1024, max: 12582912, help: 'In bytes. Larger settings are not stored; changes to them are still detected.' },
	{ key: 'limits.changePaths', label: 'Settings listed per change', kind: 'int', group: 'Performance', fallback: '100', min: 1, max: 5000, help: 'How many differing settings a change record lists before it only counts them.' },
	{ key: 'retention.logsDays', label: 'Keep logs for', kind: 'int', group: 'Retention', fallback: '30', min: -1, max: 36500, restart: true, help: 'Days. -1 keeps them for ever.' },
	{ key: 'retention.runsDays', label: 'Keep run records for', kind: 'int', group: 'Retention', fallback: '90', min: -1, max: 36500, restart: true, help: 'Days. -1 keeps them for ever.' },
	{ key: 'retention.changesDays', label: 'Keep the change record for', kind: 'int', group: 'Retention', fallback: '365', min: -1, max: 36500, restart: true, help: 'Days. -1 keeps it for ever.' },
	{ key: 'logging.level', label: 'Local log level', kind: 'enum', group: 'Logging', fallback: 'info', options: LEVELS, restart: true, help: 'What the collector writes to its own log.' },
	{ key: 'logging.mongoLevel', label: 'Dashboard log level', kind: 'enum', group: 'Logging', fallback: 'info', options: LEVELS, restart: true, help: 'What the collector sends to the logs shown in the collector monitor.' },
	{ key: 'logging.format', label: 'Local log format', kind: 'enum', group: 'Logging', fallback: 'text', options: ['text', 'json'], restart: true, help: 'The format of the collector\'s own log.' },
	{ key: 'mongo.uri', label: 'MongoDB address', kind: 'secret', group: 'Database', restart: true, help: 'The connection string the collector stores to. It usually holds a password: prefer a Key Vault reference.' },
	{ key: 'mongo.database', label: 'Database name', kind: 'text', group: 'Database', fallback: 'azconfigdrift', restart: true, help: 'This dashboard reads the database named by AZ_CONFIG_DRIFT_DB; keep the two the same.' },
	{ key: 'mongo.ensureIndexes', label: 'Create indexes at start', kind: 'bool', group: 'Database', fallback: 'true', restart: true, help: 'Turn off when the collector\'s account may not create indexes, and run -init-db once instead.' },
];

// prettier-ignore
export const TENANT_FIELDS: readonly FieldSpec[] = [
	{ key: 'tenantName', label: 'Name', kind: 'text', group: 'Tenant', help: 'The label stored on everything collected from this tenant.' },
	{ key: 'clientId', label: 'Application (client) ID', kind: 'text', group: 'Tenant', help: 'The app registration the collector signs in as.' },
	{ key: 'clientSecret', label: 'Client secret', kind: 'secret', group: 'Tenant', help: 'The app registration\'s secret.' },
	{ key: 'cloud', label: 'Cloud', kind: 'enum', group: 'Tenant', fallback: 'public', options: ['public', 'usgovernment', 'china'], help: 'Which Microsoft cloud the tenant is in.' },
	{ key: 'platforms', label: 'Collect', kind: 'list', group: 'Tenant', fallback: 'azure, m365', options: ['azure', 'm365'], help: 'azure, m365 or both.' },
	{ key: 'subscriptions', label: 'Only these subscriptions', kind: 'list', group: 'Azure', help: 'Subscription IDs. Empty collects everything the application can read, including what sits above subscriptions.' },
	{ key: 'excludeSubscriptions', label: 'Leave out these subscriptions', kind: 'list', group: 'Azure', help: 'Subscription IDs.' },
	{ key: 'username', label: 'Service account', kind: 'text', group: 'Service account', help: 'A user for Microsoft Graph sources without application permissions. It cannot have MFA.' },
	{ key: 'password', label: 'Service account password', kind: 'secret', group: 'Service account', help: 'Prefer a Key Vault reference.' },
	{ key: 'delegatedClientId', label: 'Public client application', kind: 'text', group: 'Service account', help: 'Optional: a separate application with public client flows allowed, to sign the service account in to.' },
	{ key: 'initialDomain', label: 'Initial domain', kind: 'text', group: 'Exchange Online', help: 'The tenant\'s onmicrosoft.com domain. Read from Microsoft Graph when empty.' },
];

export const GUID = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;

const UNITS: Record<string, number> = { ns: 1e-9, us: 1e-6, µs: 1e-6, ms: 1e-3, s: 1, m: 60, h: 3600 };

/** Seconds in a Go duration such as "1h30m", or null when it is not one. */
export function durationSeconds(text: string): number | null {
	if (!/^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/.test(text)) return null;
	let total = 0;
	for (const m of text.matchAll(/(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g)) total += Number(m[1]) * UNITS[m[2]];
	return total;
}

/** A list written with commas, spaces, semicolons or line breaks. */
export function splitList(text: string): string[] {
	return [...new Set(text.split(/[\s,;]+/).filter(Boolean))];
}

/**
 * Checks what was entered for a field and returns it as it is stored, or
 * the reason it cannot be. Mirrors the collector's own checks, so that
 * nothing the dashboard saves is ignored there.
 */
export function checkField(f: FieldSpec, raw: string): { value: string | number | boolean | string[] } | { error: string } {
	const text = raw.trim();
	switch (f.kind) {
		case 'duration': {
			const s = durationSeconds(text);
			if (s === null) return { error: `${f.label}: write a duration such as 6h, 90m or 30s` };
			if (s < (f.minSeconds ?? 0) || (f.maxSeconds !== undefined && s > f.maxSeconds)) {
				return { error: `${f.label}: must be ${f.maxSeconds === undefined ? `at least ${f.minSeconds}s` : `between ${f.minSeconds}s and ${f.maxSeconds}s`}` };
			}
			return { value: text };
		}
		case 'int': {
			if (!/^-?\d+$/.test(text)) return { error: `${f.label}: write a whole number` };
			const n = Number(text);
			if (n < (f.min ?? -Infinity) || n > (f.max ?? Infinity)) return { error: `${f.label}: must be between ${f.min} and ${f.max}` };
			return { value: n };
		}
		case 'bool':
			if (text !== 'true' && text !== 'false') return { error: `${f.label}: must be on or off` };
			return { value: text === 'true' };
		case 'enum': {
			const v = text.toLowerCase();
			if (!f.options?.includes(v)) return { error: `${f.label}: must be one of ${f.options?.join(', ')}` };
			return { value: v };
		}
		case 'list': {
			const items = splitList(text).map((x) => (f.options ? x.toLowerCase() : x));
			if (f.options && items.some((x) => !f.options!.includes(x))) return { error: `${f.label}: may hold ${f.options.join(' and ')}` };
			if (f.key.toLowerCase().includes('subscription') && items.some((x) => !GUID.test(x.toLowerCase()))) return { error: `${f.label}: these are subscription IDs` };
			return { value: f.key.toLowerCase().includes('subscription') ? items.map((x) => x.toLowerCase()) : items };
		}
		default:
			if (text.length > 2000) return { error: `${f.label}: too long` };
			return { value: text };
	}
}
