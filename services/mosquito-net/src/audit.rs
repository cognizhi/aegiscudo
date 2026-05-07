use aegiscudo_core::AuditEvent;
use sqlx::{PgPool, postgres::PgPoolOptions, types::Json};

#[derive(Debug, Clone)]
pub struct PostgresAuditEventRepository {
    pool: PgPool,
}

impl PostgresAuditEventRepository {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub async fn insert(&self, event: &AuditEvent) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO audit_events (
              id,
              tenant_id,
              actor,
              action,
              resource,
              trace_id,
              metadata,
              occurred_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(event.id)
        .bind(event.tenant_id)
        .bind(&event.actor)
        .bind(&event.action)
        .bind(&event.resource)
        .bind(&event.trace_id)
        .bind(Json(event.metadata.clone()))
        .bind(event.occurred_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
