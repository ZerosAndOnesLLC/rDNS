-- rDNS PostgreSQL schema for zone storage

CREATE TABLE IF NOT EXISTS zones (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    soa_mname   TEXT NOT NULL,
    soa_rname   TEXT NOT NULL,
    soa_serial  BIGINT NOT NULL DEFAULT 1,
    soa_refresh INTEGER NOT NULL DEFAULT 3600,
    soa_retry   INTEGER NOT NULL DEFAULT 900,
    soa_expire  INTEGER NOT NULL DEFAULT 604800,
    soa_minimum INTEGER NOT NULL DEFAULT 300,
    soa_ttl     INTEGER NOT NULL DEFAULT 3600,
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS records (
    id          BIGSERIAL PRIMARY KEY,
    zone_id     BIGINT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    rtype       TEXT NOT NULL,
    rclass      TEXT NOT NULL DEFAULT 'IN',
    ttl         INTEGER NOT NULL DEFAULT 3600,
    rdata       TEXT NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_records_zone_id ON records(zone_id);
CREATE INDEX IF NOT EXISTS idx_records_name_rtype ON records(name, rtype);
CREATE INDEX IF NOT EXISTS idx_records_zone_name ON records(zone_id, name);
CREATE INDEX IF NOT EXISTS idx_zones_name ON zones(name);
CREATE INDEX IF NOT EXISTS idx_records_active ON records(active) WHERE active = TRUE;

-- Notify function for real-time zone change detection
CREATE OR REPLACE FUNCTION notify_zone_change() RETURNS trigger AS $$
DECLARE
    zone_name TEXT;
BEGIN
    IF TG_TABLE_NAME = 'zones' THEN
        zone_name := COALESCE(NEW.name, OLD.name);
    ELSE
        SELECT z.name INTO zone_name FROM zones z WHERE z.id = COALESCE(NEW.zone_id, OLD.zone_id);
    END IF;

    PERFORM pg_notify('rdns_zone_change', zone_name);
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Triggers for change notification
DROP TRIGGER IF EXISTS zones_change_trigger ON zones;
CREATE TRIGGER zones_change_trigger
    AFTER INSERT OR UPDATE OR DELETE ON zones
    FOR EACH ROW EXECUTE FUNCTION notify_zone_change();

DROP TRIGGER IF EXISTS records_change_trigger ON records;
CREATE TRIGGER records_change_trigger
    AFTER INSERT OR UPDATE OR DELETE ON records
    FOR EACH ROW EXECUTE FUNCTION notify_zone_change();
