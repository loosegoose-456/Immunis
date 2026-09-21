-- Incident ledger. OWNER: Member 2.
-- Durable Object storage is working memory (fast, per-IP, pruned). This is the
-- long-term record: what happened, what we deployed, and what we refused to deploy.
--
-- Apply locally:  npm run db:init
-- Apply remotely: npm run db:init:remote

CREATE TABLE IF NOT EXISTS incidents (
	id             TEXT PRIMARY KEY,
	ip             TEXT NOT NULL,
	opened_at      INTEGER NOT NULL,
	last_event_at  INTEGER NOT NULL,
	closed_at      INTEGER,
	attack_class   TEXT,
	fingerprint    TEXT,
	event_count    INTEGER NOT NULL DEFAULT 0,
	peak_score     REAL NOT NULL DEFAULT 0,
	stage          TEXT,
	status         TEXT,
	analysis_count INTEGER NOT NULL DEFAULT 0,
	summary        TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_opened_at   ON incidents (opened_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_ip          ON incidents (ip);
CREATE INDEX IF NOT EXISTS idx_incidents_fingerprint ON incidents (fingerprint);

CREATE TABLE IF NOT EXISTS mitigations (
	id            TEXT PRIMARY KEY,
	incident_id   TEXT,
	ip            TEXT,
	kind          TEXT,
	action        TEXT,
	pattern       TEXT,
	flags         TEXT,
	deployed_at   INTEGER NOT NULL,
	expires_at    INTEGER,
	revoked_at    INTEGER,
	revoke_reason TEXT,
	source        TEXT,
	diagnosis     TEXT,
	-- JSON ValidationResult: why we believed this rule was safe to deploy.
	validation    TEXT
);

CREATE INDEX IF NOT EXISTS idx_mitigations_incident ON mitigations (incident_id);
CREATE INDEX IF NOT EXISTS idx_mitigations_active   ON mitigations (expires_at, revoked_at);

-- Append-only. `rule_rejected` rows are the evidence that the Commander vetoed an
-- unsafe generated rule rather than shipping it.
CREATE TABLE IF NOT EXISTS audit_log (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	ts     INTEGER NOT NULL,
	ip     TEXT,
	kind   TEXT NOT NULL,
	detail TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts   ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit_log (kind);
