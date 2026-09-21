/**
 * Attack classification and fingerprinting. OWNER: Member 2.
 *
 * Two jobs:
 *  1. Turn a raw request into a typed `Classification` so the policy engine can score it.
 *  2. Produce a *fingerprint* — a hash of the attack's shape, not its literals — so the
 *     same exploit launched from 50 rotating IPs collapses to one identifier. That is
 *     what lets CampaignTracker notice a botnet.
 */

import type { AttackClass, Classification, SuspiciousEvent } from '../types';

interface Detector {
	attackClass: AttackClass;
	severity: number;
	/** Each pattern that fires counts as one independent indicator. */
	patterns: { name: string; re: RegExp }[];
}

const DETECTORS: Detector[] = [
	{
		attackClass: 'log4shell',
		severity: 95,
		patterns: [
			{ name: 'jndi lookup', re: /\$\{\s*jndi\s*:\s*(ldap|ldaps|rmi|dns|iiop|corba|nis)/i },
			{ name: 'nested ${} obfuscation', re: /\$\{[^}]*\$\{/ },
		],
	},
	{
		attackClass: 'rce',
		severity: 92,
		patterns: [
			{ name: 'shell chaining', re: /[;&|]\s*(cat|ls|id|whoami|uname|curl|wget|chmod|rm)\s/i },
			{ name: 'command substitution', re: /\$\([^)]{1,80}\)/ },
			{ name: 'reverse shell', re: /(nc|ncat)\s+-[a-z]*e|bash\s+-i\s*>&|\/dev\/tcp\//i },
			{ name: 'interpreter one-liner', re: /(python[23]?|perl|ruby|php)\s+-[ecr]\s/i },
			{ name: 'template injection', re: /\{\{\s*[\w.]*(config|self|class|mro|globals)/i },
		],
	},
	{
		attackClass: 'sqli',
		severity: 85,
		patterns: [
			{ name: 'union select', re: /\bunion\b[\s\S]{0,40}?\bselect\b/i },
			{ name: 'quoted SQL comment', re: /['"`]\s*(?:--|#|\/\*)/ },
			{ name: 'tautology', re: /(\bor\b|\band\b)\s*['"`]?\s*(\d+)\s*=\s*\2\b/i },
			{ name: 'quoted tautology', re: /['"`]\s*(or|and)\s*['"`]?[^'"`]{0,10}['"`]?\s*=\s*['"`]?[^'"`]{0,10}['"`]?\s*(--|#|\/\*)/i },
			{ name: 'time-based blind', re: /\b(sleep|pg_sleep|waitfor\s+delay|benchmark)\s*\(/i },
			{ name: 'schema probing', re: /\b(information_schema|sysobjects|pg_catalog|sqlite_master)\b/i },
			{ name: 'stacked destructive query', re: /;\s*(drop|truncate|delete\s+from|update)\s+\w/i },
			{ name: 'xp_cmdshell', re: /\bxp_cmdshell\b/i },
			{ name: 'comment terminator', re: /(--|#|\/\*)\s*$/ },
		],
	},
	{
		attackClass: 'ssrf',
		severity: 78,
		patterns: [
			{ name: 'cloud metadata endpoint', re: /(169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com)/i },
			{ name: 'loopback target', re: /(127\.0\.0\.1|0\.0\.0\.0|\[::1\]|localhost)\s*:\s*\d{2,5}/i },
			{ name: 'non-http scheme', re: /\b(file|gopher|dict|ftp):\/\//i },
		],
	},
	{
		attackClass: 'path_traversal',
		severity: 74,
		patterns: [
			{ name: 'dot-dot-slash', re: /(\.\.[\/\\]){2,}/ },
			{ name: 'encoded traversal', re: /(%2e%2e(%2f|%5c)|%252e%252e)/i },
			{ name: 'sensitive file', re: /\/(etc\/(passwd|shadow)|proc\/self\/environ)|\bc:\\windows\\/i },
		],
	},
	{
		attackClass: 'nosqli',
		severity: 70,
		patterns: [
			{ name: 'mongo operator injection', re: /["']?\$(ne|gt|gte|lt|lte|where|regex|expr|function)["']?\s*[:=]/i },
			{ name: 'js where clause', re: /\$where[\s\S]{0,20}function\s*\(/i },
		],
	},
	{
		attackClass: 'xss',
		severity: 65,
		patterns: [
			{ name: 'script tag', re: /<\s*script[\s>]/i },
			{ name: 'inline event handler', re: /\bon(error|load|mouseover|focus|click|toggle)\s*=/i },
			{ name: 'javascript: uri', re: /javascript\s*:/i },
			{ name: 'cookie exfiltration', re: /document\s*\.\s*cookie/i },
			{ name: 'svg/iframe vector', re: /<\s*(svg|iframe|object|embed)\b[^>]*(onload|src\s*=\s*["']?\s*(javascript|data):)/i },
		],
	},
	{
		attackClass: 'scanner',
		severity: 45,
		patterns: [
			{ name: 'known scanner UA', re: /\b(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|feroxbuster|wpscan|havij|zgrab|nuclei)\b/i },
			{ name: 'secret file probe', re: /\/(\.env|\.git\/config|\.aws\/credentials|\.ssh\/id_rsa)\b/i },
			{ name: 'admin surface probe', re: /\/(wp-admin|wp-login\.php|phpmyadmin|adminer\.php|xmlrpc\.php|actuator\/env)\b/i },
		],
	},
];

/** Cheap, stable, non-cryptographic hash. We need determinism, not collision resistance. */
export function fnv1a(input: string): string {
	let h = 0x811c9dc5;
	for (let i = 0; i < input.length; i++) {
		h ^= input.charCodeAt(i);
		h = Math.imul(h, 0x01000193) >>> 0;
	}
	return h.toString(16).padStart(8, '0');
}

/** Percent-decode without throwing on malformed input (attackers send malformed input). */
function safeDecode(input: string): string {
	let current = input;
	// Two passes: double-encoding is a standard WAF bypass.
	for (let i = 0; i < 2; i++) {
		try {
			const next = decodeURIComponent(current.replace(/\+/g, ' '));
			if (next === current) break;
			current = next;
		} catch {
			break;
		}
	}
	return current;
}

/** Collapse literals so two runs of the same exploit hash identically. */
export function normalize(input: string): string {
	return input
		.toLowerCase()
		.replace(/['"`][^'"`]{0,64}['"`]/g, 'S')
		.replace(/\b\d+\b/g, 'N')
		.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, 'U')
		.replace(/\s+/g, ' ')
		.trim();
}

/** `/api/users/8821/orders/abc-123` -> `/api/users/:id/orders/:id` */
export function pathTemplate(rawUrl: string): string {
	let pathname: string;
	try {
		pathname = new URL(rawUrl).pathname;
	} catch {
		pathname = rawUrl.split('?')[0] || '/';
	}
	return (
		pathname
			.split('/')
			.map((segment) => {
				if (!segment) return segment;
				if (/^\d+$/.test(segment)) return ':id';
				if (/^[0-9a-f]{8}-[0-9a-f-]{20,}$/i.test(segment)) return ':id';
				if (/^[0-9a-f]{16,}$/i.test(segment)) return ':id';
				return segment;
			})
			.join('/') || '/'
	);
}

/**
 * Classify a single suspicious request.
 *
 * Severity is the winning detector's baseline, nudged up by how many *independent*
 * indicators fired — one `<script` could be a blog comment, but `<script` plus
 * `document.cookie` plus an `onerror=` handler is not an accident.
 */
/**
 * The attacker-controlled part of a URL. The host is ours, so scanning it makes every
 * request to `localhost:8787` in local dev look like an SSRF probe.
 */
function requestTarget(url: string): string {
	try {
		const parsed = new URL(url);
		return parsed.pathname + parsed.search;
	} catch {
		return url; // relative or malformed: scan as-is
	}
}

export function classify(event: SuspiciousEvent): Classification {
	const decodedUrl = safeDecode(requestTarget(event.url ?? ''));
	const decodedPayload = safeDecode(event.payload ?? '');
	const userAgent = event.userAgent ?? event.headers?.['user-agent'] ?? '';
	// Cap the scan surface so a 1MB body can't stall the isolate on backtracking.
	const haystack = `${decodedUrl}\n${decodedPayload}\n${userAgent}`.slice(0, 16_384);

	let best: { detector: Detector; hits: string[] } | undefined;
	for (const detector of DETECTORS) {
		const hits: string[] = [];
		for (const pattern of detector.patterns) {
			if (pattern.re.test(haystack)) hits.push(pattern.name);
		}
		if (!hits.length) continue;
		// Prefer the more severe class; break ties on indicator count.
		const better =
			!best ||
			detector.severity > best.detector.severity ||
			(detector.severity === best.detector.severity && hits.length > best.hits.length);
		if (better) best = { detector, hits };
	}

	const template = pathTemplate(event.url ?? '/');

	if (!best) {
		return {
			attackClass: 'unknown',
			severity: 25,
			confidence: 0.2,
			indicators: [],
			fingerprint: fnv1a(`unknown|${template}|${normalize(haystack).slice(0, 160)}`),
			pathTemplate: template,
		};
	}

	const indicators = best.hits;
	// 1 indicator -> 0.55, 2 -> 0.75, 3 -> 0.87, capped at 0.97.
	const confidence = Math.min(0.97, 1 - Math.pow(0.45, indicators.length));
	const severity = Math.min(100, Math.round(best.detector.severity + (indicators.length - 1) * 4));

	return {
		attackClass: best.detector.attackClass,
		severity,
		confidence,
		indicators,
		fingerprint: fnv1a(`${best.detector.attackClass}|${template}|${indicators.slice().sort().join(',')}`),
		pathTemplate: template,
	};
}

/**
 * Pull the literal substrings that actually tripped the detectors.
 * These are the candidate anchors for a generated WAF rule, and the proof set we
 * check a rule against before deploying it.
 */
export function extractSignatureSamples(event: SuspiciousEvent, limit = 4): string[] {
	const decoded = `${safeDecode(event.url ?? '')} ${safeDecode(event.payload ?? '')}`.slice(0, 16_384);
	const samples: string[] = [];
	for (const detector of DETECTORS) {
		for (const pattern of detector.patterns) {
			const match = decoded.match(pattern.re);
			if (match?.[0]) samples.push(match[0].trim().slice(0, 120));
			if (samples.length >= limit) return samples;
		}
	}
	return samples;
}
