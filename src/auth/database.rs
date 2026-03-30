//! PostgreSQL backend for zone storage.
//! Only compiled when the `postgres` feature is enabled.

#[cfg(feature = "postgres")]
mod inner {
    use crate::auth::catalog::ZoneCatalog;
    use crate::auth::zone::Zone;
    use crate::protocol::name::DnsName;
    use crate::protocol::rdata::{RData, SoaData};
    use crate::protocol::record::{RecordClass, RecordType, ResourceRecord};
    use sqlx::postgres::{PgListener, PgPool, PgPoolOptions};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::time::Duration;

    /// Database-backed zone loader.
    pub struct DatabaseBackend {
        pool: PgPool,
        catalog: ZoneCatalog,
    }

    impl DatabaseBackend {
        /// Connect to the database and create the backend.
        pub async fn connect(
            connection_string: &str,
            catalog: ZoneCatalog,
        ) -> anyhow::Result<Self> {
            let pool = PgPoolOptions::new()
                .max_connections(10)
                .acquire_timeout(Duration::from_secs(5))
                .connect(connection_string)
                .await?;

            tracing::info!("Connected to PostgreSQL");

            Ok(Self { pool, catalog })
        }

        /// Run database migrations.
        pub async fn migrate(&self) -> anyhow::Result<()> {
            sqlx::migrate!("./migrations").run(&self.pool).await?;
            tracing::info!("Database migrations applied");
            Ok(())
        }

        /// Load all active zones from the database into the catalog.
        pub async fn load_all_zones(&self) -> anyhow::Result<usize> {
            let zones = sqlx::query_as::<_, ZoneRow>(
                "SELECT id, name, soa_mname, soa_rname, soa_serial, soa_refresh, \
                 soa_retry, soa_expire, soa_minimum, soa_ttl \
                 FROM zones WHERE active = TRUE",
            )
            .fetch_all(&self.pool)
            .await?;

            let mut count = 0;
            for zone_row in &zones {
                match self.load_zone(zone_row).await {
                    Ok(zone) => {
                        let record_count: usize =
                            zone.rrsets.values().map(|rs| rs.records.len()).sum();
                        tracing::info!(
                            zone = %zone_row.name,
                            records = record_count,
                            "Loaded zone from database"
                        );
                        self.catalog.insert(zone);
                        count += 1;
                    }
                    Err(e) => {
                        tracing::error!(
                            zone = %zone_row.name,
                            error = %e,
                            "Failed to load zone from database"
                        );
                    }
                }
            }

            Ok(count)
        }

        /// Load a single zone by row.
        async fn load_zone(&self, zone_row: &ZoneRow) -> anyhow::Result<Zone> {
            let origin = DnsName::from_str(&zone_row.name)
                .map_err(|e| anyhow::anyhow!("Invalid zone name '{}': {}", zone_row.name, e))?;

            let soa = SoaData {
                mname: DnsName::from_str(&zone_row.soa_mname)?,
                rname: DnsName::from_str(&zone_row.soa_rname)?,
                serial: zone_row.soa_serial as u32,
                refresh: zone_row.soa_refresh as u32,
                retry: zone_row.soa_retry as u32,
                expire: zone_row.soa_expire as u32,
                minimum: zone_row.soa_minimum as u32,
            };

            let mut zone = Zone::new(origin, soa, zone_row.soa_ttl as u32);

            // Load records
            let records = sqlx::query_as::<_, RecordRow>(
                "SELECT name, rtype, rclass, ttl, rdata \
                 FROM records WHERE zone_id = $1 AND active = TRUE",
            )
            .bind(zone_row.id)
            .fetch_all(&self.pool)
            .await?;

            for record in &records {
                match parse_record_row(record) {
                    Ok(rr) => zone.add_record(rr),
                    Err(e) => {
                        tracing::warn!(
                            zone = %zone_row.name,
                            record = %record.name,
                            rtype = %record.rtype,
                            error = %e,
                            "Failed to parse record"
                        );
                    }
                }
            }

            Ok(zone)
        }

        /// Reload a specific zone from the database.
        pub async fn reload_zone(&self, zone_name: &str) -> anyhow::Result<()> {
            let zone_row = sqlx::query_as::<_, ZoneRow>(
                "SELECT id, name, soa_mname, soa_rname, soa_serial, soa_refresh, \
                 soa_retry, soa_expire, soa_minimum, soa_ttl \
                 FROM zones WHERE name = $1 AND active = TRUE",
            )
            .bind(zone_name)
            .fetch_optional(&self.pool)
            .await?;

            match zone_row {
                Some(row) => {
                    let zone = self.load_zone(&row).await?;
                    self.catalog.insert(zone);
                    tracing::info!(zone = zone_name, "Reloaded zone from database");
                }
                None => {
                    // Zone removed or deactivated — remove from catalog
                    if let Ok(name) = DnsName::from_str(zone_name) {
                        self.catalog.remove(&name);
                        tracing::info!(zone = zone_name, "Removed zone (no longer active)");
                    }
                }
            }

            Ok(())
        }

        /// Listen for PostgreSQL NOTIFY events and reload zones on change.
        pub async fn listen_for_changes(self: Arc<Self>) -> anyhow::Result<()> {
            let mut listener = PgListener::connect_with(&self.pool).await?;
            listener.listen("rdns_zone_change").await?;
            tracing::info!("Listening for zone change notifications");

            loop {
                match listener.recv().await {
                    Ok(notification) => {
                        let zone_name = notification.payload();
                        tracing::info!(zone = zone_name, "Zone change notification received");

                        if let Err(e) = self.reload_zone(zone_name).await {
                            tracing::error!(
                                zone = zone_name,
                                error = %e,
                                "Failed to reload zone after notification"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "LISTEN error, reconnecting...");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
    }

    #[derive(sqlx::FromRow)]
    struct ZoneRow {
        id: i64,
        name: String,
        soa_mname: String,
        soa_rname: String,
        soa_serial: i64,
        soa_refresh: i32,
        soa_retry: i32,
        soa_expire: i32,
        soa_minimum: i32,
        soa_ttl: i32,
    }

    #[derive(sqlx::FromRow)]
    struct RecordRow {
        name: String,
        rtype: String,
        rclass: String,
        ttl: i32,
        rdata: String,
    }

    /// Parse a database record row into a ResourceRecord.
    fn parse_record_row(row: &RecordRow) -> anyhow::Result<ResourceRecord> {
        let name = DnsName::from_str(&row.name)?;
        let rtype = parse_rtype(&row.rtype)?;
        let rclass = parse_rclass(&row.rclass);
        let rdata = parse_rdata_str(rtype, &row.rdata)?;

        Ok(ResourceRecord {
            name,
            rtype,
            rclass,
            ttl: row.ttl as u32,
            rdata,
        })
    }

    fn parse_rtype(s: &str) -> anyhow::Result<RecordType> {
        match s.to_uppercase().as_str() {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::AAAA),
            "NS" => Ok(RecordType::NS),
            "CNAME" => Ok(RecordType::CNAME),
            "SOA" => Ok(RecordType::SOA),
            "PTR" => Ok(RecordType::PTR),
            "MX" => Ok(RecordType::MX),
            "TXT" => Ok(RecordType::TXT),
            "SRV" => Ok(RecordType::SRV),
            "CAA" => Ok(RecordType::CAA),
            _ => anyhow::bail!("Unknown record type: {}", s),
        }
    }

    fn parse_rclass(s: &str) -> RecordClass {
        match s.to_uppercase().as_str() {
            "IN" => RecordClass::IN,
            "CH" => RecordClass::CH,
            _ => RecordClass::IN,
        }
    }

    /// Parse RDATA from its text representation (as stored in the database).
    fn parse_rdata_str(rtype: RecordType, rdata: &str) -> anyhow::Result<RData> {
        match rtype {
            RecordType::A => {
                let ip: Ipv4Addr = rdata.trim().parse()?;
                Ok(RData::A(ip))
            }
            RecordType::AAAA => {
                let ip: Ipv6Addr = rdata.trim().parse()?;
                Ok(RData::AAAA(ip))
            }
            RecordType::NS => Ok(RData::NS(DnsName::from_str(rdata.trim())?)),
            RecordType::CNAME => Ok(RData::CNAME(DnsName::from_str(rdata.trim())?)),
            RecordType::PTR => Ok(RData::PTR(DnsName::from_str(rdata.trim())?)),
            RecordType::MX => {
                let parts: Vec<&str> = rdata.trim().splitn(2, ' ').collect();
                if parts.len() != 2 {
                    anyhow::bail!("Invalid MX rdata: {}", rdata);
                }
                let preference: u16 = parts[0].parse()?;
                let exchange = DnsName::from_str(parts[1])?;
                Ok(RData::MX {
                    preference,
                    exchange,
                })
            }
            RecordType::TXT => {
                let text = rdata.trim().trim_matches('"');
                Ok(RData::TXT(vec![text.as_bytes().to_vec()]))
            }
            RecordType::SRV => {
                let parts: Vec<&str> = rdata.trim().split_whitespace().collect();
                if parts.len() != 4 {
                    anyhow::bail!("Invalid SRV rdata: {}", rdata);
                }
                Ok(RData::SRV(crate::protocol::rdata::SrvData {
                    priority: parts[0].parse()?,
                    weight: parts[1].parse()?,
                    port: parts[2].parse()?,
                    target: DnsName::from_str(parts[3])?,
                }))
            }
            RecordType::CAA => {
                let parts: Vec<&str> = rdata.trim().splitn(3, ' ').collect();
                if parts.len() != 3 {
                    anyhow::bail!("Invalid CAA rdata: {}", rdata);
                }
                Ok(RData::CAA(crate::protocol::rdata::CaaData {
                    flags: parts[0].parse()?,
                    tag: parts[1].to_string(),
                    value: parts[2].trim_matches('"').as_bytes().to_vec(),
                }))
            }
            _ => anyhow::bail!("Unsupported record type for DB: {:?}", rtype),
        }
    }
}

#[cfg(feature = "postgres")]
pub use inner::DatabaseBackend;
