use dataxlr8_mcp_core::mcp::{empty_schema, error_result, get_i64, get_str, json_result, make_schema};
use dataxlr8_mcp_core::Database;
use rmcp::model::*;
use rmcp::service::{RequestContext, RoleServer};
use rmcp::ServerHandler;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

// ============================================================================
// Data types
// ============================================================================

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditLog {
    pub id: String,
    pub agent: String,
    pub action: String,
    pub entity_type: String,
    pub entity_id: String,
    pub details: serde_json::Value,
    pub before_state: Option<serde_json::Value>,
    pub after_state: Option<serde_json::Value>,
    pub ip: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct DailySummaryRow {
    pub date: String,
    pub action: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct DiffResult {
    pub id: String,
    pub agent: String,
    pub action: String,
    pub entity_type: String,
    pub entity_id: String,
    pub before_state: Option<serde_json::Value>,
    pub after_state: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct ComplianceEntry {
    pub agent: String,
    pub action: String,
    pub entity_type: String,
    pub entity_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub has_before: bool,
    pub has_after: bool,
}

#[derive(Debug, Serialize)]
pub struct ComplianceReport {
    pub period_start: String,
    pub period_end: String,
    pub total_actions: i64,
    pub unique_agents: i64,
    pub entries: Vec<ComplianceEntry>,
}

#[derive(Debug, Serialize)]
pub struct PurgeResult {
    pub deleted: u64,
    pub older_than_days: i64,
}

// ============================================================================
// Tool definitions
// ============================================================================

fn build_tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "log_action".into(),
            title: None,
            description: Some("Record an audit log entry — who did what to which entity".into()),
            input_schema: make_schema(
                serde_json::json!({
                    "agent": { "type": "string", "description": "Who performed the action (agent name, user ID, or system)" },
                    "action": { "type": "string", "description": "What was done (e.g. create, update, delete, login)" },
                    "entity_type": { "type": "string", "description": "Type of entity affected (e.g. deal, contact, flag)" },
                    "entity_id": { "type": "string", "description": "ID of the entity affected" },
                    "details": { "type": "object", "description": "Additional context as JSON" },
                    "before": { "type": "object", "description": "State before the change (JSON snapshot)" },
                    "after": { "type": "object", "description": "State after the change (JSON snapshot)" },
                    "ip": { "type": "string", "description": "IP address of the caller" }
                }),
                vec!["agent", "action"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "query_audit".into(),
            title: None,
            description: Some("Query audit logs with filters: agent, action, entity_type, entity_id, date range. All filters are optional.".into()),
            input_schema: make_schema(
                serde_json::json!({
                    "agent": { "type": "string", "description": "Filter by agent name" },
                    "action": { "type": "string", "description": "Filter by action type" },
                    "entity_type": { "type": "string", "description": "Filter by entity type" },
                    "entity_id": { "type": "string", "description": "Filter by entity ID" },
                    "since": { "type": "string", "description": "Start date (ISO 8601, e.g. 2025-01-01)" },
                    "until": { "type": "string", "description": "End date (ISO 8601, e.g. 2025-12-31)" },
                    "limit": { "type": "integer", "description": "Max rows to return (default 100)" }
                }),
                vec![],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "entity_history".into(),
            title: None,
            description: Some("Get the full change history for a single entity, ordered chronologically".into()),
            input_schema: make_schema(
                serde_json::json!({
                    "entity_type": { "type": "string", "description": "Type of entity (e.g. deal, contact)" },
                    "entity_id": { "type": "string", "description": "ID of the entity" },
                    "limit": { "type": "integer", "description": "Max rows (default 100)" }
                }),
                vec!["entity_type", "entity_id"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "agent_activity".into(),
            title: None,
            description: Some("Get all actions performed by a specific agent, ordered by most recent first".into()),
            input_schema: make_schema(
                serde_json::json!({
                    "agent": { "type": "string", "description": "Agent name to look up" },
                    "since": { "type": "string", "description": "Start date (ISO 8601)" },
                    "limit": { "type": "integer", "description": "Max rows (default 100)" }
                }),
                vec!["agent"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "daily_summary".into(),
            title: None,
            description: Some("Get action counts grouped by day and action type".into()),
            input_schema: make_schema(
                serde_json::json!({
                    "since": { "type": "string", "description": "Start date (ISO 8601, default 7 days ago)" },
                    "until": { "type": "string", "description": "End date (ISO 8601, default now)" }
                }),
                vec![],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "diff_changes".into(),
            title: None,
            description: Some("Show the before/after state diff for a specific audit log entry by ID".into()),
            input_schema: make_schema(
                serde_json::json!({
                    "id": { "type": "string", "description": "Audit log entry ID" }
                }),
                vec!["id"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "compliance_report".into(),
            title: None,
            description: Some("Generate a compliance report: all changes in a time period with actor attribution, counts, and unique agents".into()),
            input_schema: make_schema(
                serde_json::json!({
                    "since": { "type": "string", "description": "Period start (ISO 8601)" },
                    "until": { "type": "string", "description": "Period end (ISO 8601, default now)" },
                    "limit": { "type": "integer", "description": "Max entries in report (default 500)" }
                }),
                vec!["since"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
        Tool {
            name: "purge_old".into(),
            title: None,
            description: Some("Delete audit logs older than N days. Returns the number of rows deleted.".into()),
            input_schema: make_schema(
                serde_json::json!({
                    "older_than_days": { "type": "integer", "description": "Delete logs older than this many days" }
                }),
                vec!["older_than_days"],
            ),
            output_schema: None,
            annotations: None,
            execution: None,
            icons: None,
            meta: None,
        },
    ]
}

// ============================================================================
// MCP Server
// ============================================================================

#[derive(Clone)]
pub struct AuditMcpServer {
    db: Database,
}

impl AuditMcpServer {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    // ---- Tool handlers ----

    async fn handle_log_action(&self, args: &serde_json::Value) -> CallToolResult {
        let agent = match get_str(args, "agent") {
            Some(a) => a,
            None => return error_result("Missing required parameter: agent"),
        };
        let action = match get_str(args, "action") {
            Some(a) => a,
            None => return error_result("Missing required parameter: action"),
        };
        let entity_type = get_str(args, "entity_type").unwrap_or_default();
        let entity_id = get_str(args, "entity_id").unwrap_or_default();
        let details = args
            .get("details")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        let before = args.get("before").cloned();
        let after = args.get("after").cloned();
        let ip = get_str(args, "ip").unwrap_or_default();

        let id = uuid::Uuid::new_v4().to_string();

        match sqlx::query_as::<_, AuditLog>(
            r#"INSERT INTO audit.logs (id, agent, action, entity_type, entity_id, details, before_state, after_state, ip)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
               RETURNING *"#,
        )
        .bind(&id)
        .bind(&agent)
        .bind(&action)
        .bind(&entity_type)
        .bind(&entity_id)
        .bind(&details)
        .bind(&before)
        .bind(&after)
        .bind(&ip)
        .fetch_one(self.db.pool())
        .await
        {
            Ok(log) => {
                info!(agent = agent, action = action, entity_type = entity_type, entity_id = entity_id, "Audit log recorded");
                json_result(&log)
            }
            Err(e) => {
                error!(error = %e, "Failed to insert audit log");
                error_result(&format!("Failed to log action: {e}"))
            }
        }
    }

    async fn handle_query_audit(&self, args: &serde_json::Value) -> CallToolResult {
        let agent = get_str(args, "agent");
        let action = get_str(args, "action");
        let entity_type = get_str(args, "entity_type");
        let entity_id = get_str(args, "entity_id");
        let since = get_str(args, "since");
        let until = get_str(args, "until");
        let limit = get_i64(args, "limit").unwrap_or(100).min(1000);

        // Build dynamic query with numbered parameters
        let mut conditions: Vec<String> = Vec::new();
        let mut param_idx = 0u32;

        if agent.is_some() {
            param_idx += 1;
            conditions.push(format!("agent = ${param_idx}"));
        }
        if action.is_some() {
            param_idx += 1;
            conditions.push(format!("action = ${param_idx}"));
        }
        if entity_type.is_some() {
            param_idx += 1;
            conditions.push(format!("entity_type = ${param_idx}"));
        }
        if entity_id.is_some() {
            param_idx += 1;
            conditions.push(format!("entity_id = ${param_idx}"));
        }
        if since.is_some() {
            param_idx += 1;
            conditions.push(format!("created_at >= ${param_idx}::timestamptz"));
        }
        if until.is_some() {
            param_idx += 1;
            conditions.push(format!("created_at <= ${param_idx}::timestamptz"));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        param_idx += 1;
        let sql = format!(
            "SELECT * FROM audit.logs {where_clause} ORDER BY created_at DESC LIMIT ${param_idx}"
        );

        let mut query = sqlx::query_as::<_, AuditLog>(&sql);

        // Bind in the same order as conditions
        if let Some(ref v) = agent {
            query = query.bind(v);
        }
        if let Some(ref v) = action {
            query = query.bind(v);
        }
        if let Some(ref v) = entity_type {
            query = query.bind(v);
        }
        if let Some(ref v) = entity_id {
            query = query.bind(v);
        }
        if let Some(ref v) = since {
            query = query.bind(v);
        }
        if let Some(ref v) = until {
            query = query.bind(v);
        }
        query = query.bind(limit);

        match query.fetch_all(self.db.pool()).await {
            Ok(logs) => json_result(&logs),
            Err(e) => {
                error!(error = %e, "Failed to query audit logs");
                error_result(&format!("Query failed: {e}"))
            }
        }
    }

    async fn handle_entity_history(&self, entity_type: &str, entity_id: &str, limit: i64) -> CallToolResult {
        match sqlx::query_as::<_, AuditLog>(
            "SELECT * FROM audit.logs WHERE entity_type = $1 AND entity_id = $2 ORDER BY created_at ASC LIMIT $3",
        )
        .bind(entity_type)
        .bind(entity_id)
        .bind(limit.min(1000))
        .fetch_all(self.db.pool())
        .await
        {
            Ok(logs) => json_result(&logs),
            Err(e) => {
                error!(error = %e, entity_type, entity_id, "Failed to fetch entity history");
                error_result(&format!("Query failed: {e}"))
            }
        }
    }

    async fn handle_agent_activity(&self, agent: &str, since: Option<&str>, limit: i64) -> CallToolResult {
        let logs = if let Some(since_val) = since {
            sqlx::query_as::<_, AuditLog>(
                "SELECT * FROM audit.logs WHERE agent = $1 AND created_at >= $2::timestamptz ORDER BY created_at DESC LIMIT $3",
            )
            .bind(agent)
            .bind(since_val)
            .bind(limit.min(1000))
            .fetch_all(self.db.pool())
            .await
        } else {
            sqlx::query_as::<_, AuditLog>(
                "SELECT * FROM audit.logs WHERE agent = $1 ORDER BY created_at DESC LIMIT $2",
            )
            .bind(agent)
            .bind(limit.min(1000))
            .fetch_all(self.db.pool())
            .await
        };

        match logs {
            Ok(logs) => json_result(&logs),
            Err(e) => {
                error!(error = %e, agent, "Failed to fetch agent activity");
                error_result(&format!("Query failed: {e}"))
            }
        }
    }

    async fn handle_daily_summary(&self, since: Option<&str>, until: Option<&str>) -> CallToolResult {
        let since_val = since.unwrap_or("now() - interval '7 days'");
        let until_val = until.unwrap_or("now()");

        // Use COALESCE-style: if user passes a date string, cast it; otherwise use SQL expression
        let sql = format!(
            r#"SELECT
                 to_char(created_at::date, 'YYYY-MM-DD') as date,
                 action,
                 count(*)::bigint as count
               FROM audit.logs
               WHERE created_at >= {}::timestamptz
                 AND created_at <= {}::timestamptz
               GROUP BY created_at::date, action
               ORDER BY date DESC, count DESC"#,
            if since.is_some() { "$1" } else { "now() - interval '7 days'" },
            if until.is_some() {
                if since.is_some() { "$2" } else { "$1" }
            } else {
                "now()"
            },
        );

        #[derive(sqlx::FromRow)]
        struct SummaryRow {
            date: String,
            action: String,
            count: i64,
        }

        let mut query = sqlx::query_as::<_, SummaryRow>(&sql);
        if let Some(s) = since {
            query = query.bind(s);
        }
        if let Some(u) = until {
            query = query.bind(u);
        }

        match query.fetch_all(self.db.pool()).await {
            Ok(rows) => {
                let result: Vec<DailySummaryRow> = rows
                    .into_iter()
                    .map(|r| DailySummaryRow {
                        date: r.date,
                        action: r.action,
                        count: r.count,
                    })
                    .collect();
                json_result(&result)
            }
            Err(e) => {
                error!(error = %e, "Failed to generate daily summary");
                error_result(&format!("Query failed: {e}"))
            }
        }
    }

    async fn handle_diff_changes(&self, id: &str) -> CallToolResult {
        match sqlx::query_as::<_, AuditLog>(
            "SELECT * FROM audit.logs WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(self.db.pool())
        .await
        {
            Ok(Some(log)) => {
                let diff = DiffResult {
                    id: log.id,
                    agent: log.agent,
                    action: log.action,
                    entity_type: log.entity_type,
                    entity_id: log.entity_id,
                    before_state: log.before_state,
                    after_state: log.after_state,
                    created_at: log.created_at,
                };
                json_result(&diff)
            }
            Ok(None) => error_result(&format!("Audit log entry '{id}' not found")),
            Err(e) => {
                error!(error = %e, id, "Failed to fetch audit log entry");
                error_result(&format!("Query failed: {e}"))
            }
        }
    }

    async fn handle_compliance_report(&self, since: &str, until: Option<&str>, limit: i64) -> CallToolResult {
        // Get summary counts
        let count_sql = if until.is_some() {
            "SELECT count(*)::bigint as total, count(DISTINCT agent)::bigint as agents FROM audit.logs WHERE created_at >= $1::timestamptz AND created_at <= $2::timestamptz"
        } else {
            "SELECT count(*)::bigint as total, count(DISTINCT agent)::bigint as agents FROM audit.logs WHERE created_at >= $1::timestamptz AND created_at <= now()"
        };

        #[derive(sqlx::FromRow)]
        struct Counts {
            total: i64,
            agents: i64,
        }

        let mut count_query = sqlx::query_as::<_, Counts>(count_sql).bind(since);
        if let Some(u) = until {
            count_query = count_query.bind(u);
        }

        let counts = match count_query.fetch_one(self.db.pool()).await {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "Failed to get compliance counts");
                return error_result(&format!("Query failed: {e}"));
            }
        };

        // Get entries
        let entries_sql = if until.is_some() {
            "SELECT agent, action, entity_type, entity_id, created_at, before_state IS NOT NULL as has_before, after_state IS NOT NULL as has_after FROM audit.logs WHERE created_at >= $1::timestamptz AND created_at <= $2::timestamptz ORDER BY created_at ASC LIMIT $3"
        } else {
            "SELECT agent, action, entity_type, entity_id, created_at, before_state IS NOT NULL as has_before, after_state IS NOT NULL as has_after FROM audit.logs WHERE created_at >= $1::timestamptz AND created_at <= now() ORDER BY created_at ASC LIMIT $2"
        };

        #[derive(sqlx::FromRow)]
        struct EntryRow {
            agent: String,
            action: String,
            entity_type: String,
            entity_id: String,
            created_at: chrono::DateTime<chrono::Utc>,
            has_before: bool,
            has_after: bool,
        }

        let mut entries_query = sqlx::query_as::<_, EntryRow>(entries_sql).bind(since);
        if let Some(u) = until {
            entries_query = entries_query.bind(u);
        }
        entries_query = entries_query.bind(limit.min(1000));

        let entries = match entries_query.fetch_all(self.db.pool()).await {
            Ok(rows) => rows
                .into_iter()
                .map(|r| ComplianceEntry {
                    agent: r.agent,
                    action: r.action,
                    entity_type: r.entity_type,
                    entity_id: r.entity_id,
                    created_at: r.created_at,
                    has_before: r.has_before,
                    has_after: r.has_after,
                })
                .collect(),
            Err(e) => {
                error!(error = %e, "Failed to get compliance entries");
                return error_result(&format!("Query failed: {e}"));
            }
        };

        let report = ComplianceReport {
            period_start: since.to_string(),
            period_end: until.unwrap_or("now").to_string(),
            total_actions: counts.total,
            unique_agents: counts.agents,
            entries,
        };

        json_result(&report)
    }

    async fn handle_purge_old(&self, older_than_days: i64) -> CallToolResult {
        if older_than_days < 1 {
            return error_result("older_than_days must be at least 1");
        }

        let interval = format!("{older_than_days} days");

        match sqlx::query("DELETE FROM audit.logs WHERE created_at < now() - $1::interval")
            .bind(&interval)
            .execute(self.db.pool())
            .await
        {
            Ok(r) => {
                let deleted = r.rows_affected();
                info!(deleted, older_than_days, "Purged old audit logs");
                json_result(&PurgeResult {
                    deleted,
                    older_than_days,
                })
            }
            Err(e) => {
                error!(error = %e, "Failed to purge audit logs");
                error_result(&format!("Purge failed: {e}"))
            }
        }
    }
}

// ============================================================================
// ServerHandler trait implementation
// ============================================================================

impl ServerHandler for AuditMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "DataXLR8 Audit MCP — record and query audit logs for all platform actions"
                    .into(),
            ),
        }
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + Send + '_ {
        async {
            Ok(ListToolsResult {
                tools: build_tools(),
                next_cursor: None,
                meta: None,
            })
        }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, rmcp::ErrorData>> + Send + '_ {
        async move {
            let args = serde_json::to_value(&request.arguments).unwrap_or(serde_json::Value::Null);
            let name_str: &str = request.name.as_ref();

            let result = match name_str {
                "log_action" => self.handle_log_action(&args).await,
                "query_audit" => self.handle_query_audit(&args).await,
                "entity_history" => {
                    let et = get_str(&args, "entity_type");
                    let ei = get_str(&args, "entity_id");
                    match (et, ei) {
                        (Some(et), Some(ei)) => {
                            let limit = get_i64(&args, "limit").unwrap_or(100);
                            self.handle_entity_history(&et, &ei, limit).await
                        }
                        _ => error_result("Missing required parameters: entity_type, entity_id"),
                    }
                }
                "agent_activity" => {
                    match get_str(&args, "agent") {
                        Some(agent) => {
                            let since = get_str(&args, "since");
                            let limit = get_i64(&args, "limit").unwrap_or(100);
                            self.handle_agent_activity(&agent, since.as_deref(), limit).await
                        }
                        None => error_result("Missing required parameter: agent"),
                    }
                }
                "daily_summary" => {
                    let since = get_str(&args, "since");
                    let until = get_str(&args, "until");
                    self.handle_daily_summary(since.as_deref(), until.as_deref()).await
                }
                "diff_changes" => {
                    match get_str(&args, "id") {
                        Some(id) => self.handle_diff_changes(&id).await,
                        None => error_result("Missing required parameter: id"),
                    }
                }
                "compliance_report" => {
                    match get_str(&args, "since") {
                        Some(since) => {
                            let until = get_str(&args, "until");
                            let limit = get_i64(&args, "limit").unwrap_or(500);
                            self.handle_compliance_report(&since, until.as_deref(), limit).await
                        }
                        None => error_result("Missing required parameter: since"),
                    }
                }
                "purge_old" => {
                    match get_i64(&args, "older_than_days") {
                        Some(days) => self.handle_purge_old(days).await,
                        None => error_result("Missing required parameter: older_than_days"),
                    }
                }
                _ => error_result(&format!("Unknown tool: {}", request.name)),
            };

            Ok(result)
        }
    }
}
