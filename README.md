# dataxlr8-audit-mcp

Audit logging and compliance tracking for DataXLR8. Track all changes with before/after state, attribution, and compliance reporting.

## Tools

| Tool | Description |
|------|-------------|
| log_action | Record an audit log entry — who did what to which entity |
| query_audit | Query audit logs with filters: agent, action, entity_type, entity_id, date range. All filters are optional. Supports pagination via limit/offset. |
| entity_history | Get the full change history for a single entity, ordered chronologically. Supports pagination via limit/offset. |
| agent_activity | Get all actions performed by a specific agent, ordered by most recent first. Supports pagination via limit/offset. |
| daily_summary | Get action counts grouped by day and action type |
| diff_changes | Show the before/after state diff for a specific audit log entry by ID |
| compliance_report | Generate a compliance report: all changes in a time period with actor attribution, counts, and unique agents. Supports pagination via limit/offset. |
| purge_old | Delete audit logs older than N days. Returns the number of rows deleted. |

## Setup

```bash
DATABASE_URL=postgres://dataxlr8:dataxlr8@localhost:5432/dataxlr8 cargo run
```

## Schema

Creates `audit.*` schema in PostgreSQL:
- `logs` - Complete audit trail with agent, action, entity info, before/after state, IP, and timestamp

## Part of

[DataXLR8](https://github.com/pdaxt) - AI-powered recruitment platform
