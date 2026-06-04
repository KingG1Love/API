-- ============================================================
-- Lab 2 — Database schema (3NF)
-- PostgreSQL 16
-- ============================================================

-- Core CVE record (one row per CVE)
CREATE TABLE IF NOT EXISTS vulnerability (
    id                  BIGSERIAL PRIMARY KEY,
    name                TEXT        NOT NULL UNIQUE,      -- CVE-ID, e.g. CVE-2024-1234
    vendor_release_date DATE        NOT NULL,
    vendor_release_url  TEXT        NOT NULL,
    url                 TEXT        NOT NULL,             -- link on cve.org
    published_date      TIMESTAMPTZ NOT NULL,
    updated_date        TIMESTAMPTZ NOT NULL,
    description         TEXT        NOT NULL
);

-- CVSS scores  (many per vulnerability, one per version+vector combo)
CREATE TABLE IF NOT EXISTS cvss_score (
    id               BIGSERIAL PRIMARY KEY,
    vulnerability_id BIGINT        NOT NULL REFERENCES vulnerability (id) ON DELETE CASCADE,
    version          TEXT          NOT NULL,              -- e.g. cvss31, cvss40
    score            NUMERIC(3, 1),
    vector           TEXT          NOT NULL,
    severity         TEXT          NOT NULL,
    UNIQUE (vulnerability_id, version, vector)
);

-- CPE strings are deduplicated in their own table
CREATE TABLE IF NOT EXISTS cpe (
    id   BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE                             -- CPE 2.3 string
);

-- Many-to-many: vulnerability <-> cpe
CREATE TABLE IF NOT EXISTS vulnerability_cpe (
    vulnerability_id BIGINT NOT NULL REFERENCES vulnerability (id) ON DELETE CASCADE,
    cpe_id           BIGINT NOT NULL REFERENCES cpe         (id) ON DELETE CASCADE,
    PRIMARY KEY (vulnerability_id, cpe_id)
);

-- CWE definitions are deduplicated (one row per CWE-ID)
CREATE TABLE IF NOT EXISTS cwe (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,                    -- CWE-ID, e.g. CWE-79
    title       TEXT NOT NULL,                           -- human-readable name
    description TEXT NOT NULL
);

-- Many-to-many: vulnerability <-> cwe
CREATE TABLE IF NOT EXISTS vulnerability_cwe (
    vulnerability_id BIGINT NOT NULL REFERENCES vulnerability (id) ON DELETE CASCADE,
    cwe_id           BIGINT NOT NULL REFERENCES cwe         (id) ON DELETE CASCADE,
    PRIMARY KEY (vulnerability_id, cwe_id)
);
