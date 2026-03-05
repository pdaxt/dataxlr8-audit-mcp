use anyhow::Result;
use sqlx::PgPool;

/// Create the audit schema in PostgreSQL if it doesn't exist.
pub async fn setup_schema(pool: &PgPool) -> Result<()> {
    sqlx::raw_sql(
        r#"
        CREATE SCHEMA IF NOT EXISTS audit;

        CREATE TABLE IF NOT EXISTS audit.logs (
            id           TEXT PRIMARY KEY,
            agent        TEXT NOT NULL,
            action       TEXT NOT NULL,
            entity_type  TEXT NOT NULL DEFAULT '',
            entity_id    TEXT NOT NULL DEFAULT '',
            details      JSONB NOT NULL DEFAULT '{}',
            before_state JSONB,
            after_state  JSONB,
            ip           TEXT NOT NULL DEFAULT '',
            created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
        );

        CREATE INDEX IF NOT EXISTS idx_logs_agent
            ON audit.logs(agent);
        CREATE INDEX IF NOT EXISTS idx_logs_entity
            ON audit.logs(entity_type, entity_id);
        CREATE INDEX IF NOT EXISTS idx_logs_created_at
            ON audit.logs(created_at);
        CREATE INDEX IF NOT EXISTS idx_logs_action
            ON audit.logs(action);
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}
