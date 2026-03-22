# Audit Log Archive

A reusable CDK construct for archiving CloudWatch Logs to S3 in Parquet format for long-term storage and analytics with Athena.

## Features

- **Parquet Format**: Columnar storage with Snappy compression (80-90% smaller than JSON)
- **Intelligent-Tiering**: Automatic cost optimization for S3 storage
- **Athena-Ready**: Pre-configured Glue database and table for immediate querying
- **Partitioned**: Date-based partitioning (year/month/day) for efficient queries
- **Encrypted**: KMS encryption for data at rest
- **Configurable Retention**: Separate retention for CloudWatch Logs and S3 archive

## Architecture

```
CloudWatch Logs → Subscription Filter → Kinesis Firehose → S3 (Parquet)
                                              ↓
                                        Glue Catalog
                                              ↓
                                          Athena
```

## Usage

```typescript
import { AuditLogArchive } from './constructs/cloudfront/logging';

const auditLogs = new AuditLogArchive(this, 'AuditLogs', {
  logGroupNames: [
    '/aws/lambda/my-function-1',
    '/aws/lambda/my-function-2',
  ],
  kmsKey: myKmsKey,
  retentionDays: 30,              // CloudWatch Logs retention (default: 30)
  archiveRetentionDays: 365,      // S3 archive retention (default: 365)
  bucketName: 'my-audit-logs',    // Optional
  databaseName: 'audit_logs',     // Optional
});
```

## Properties

| Property | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| `logGroupNames` | `string[]` | Yes | - | CloudWatch Log Groups to archive |
| `kmsKey` | `IKey` | Yes | - | KMS key for encryption |
| `retentionDays` | `number` | No | 30 | CloudWatch Logs retention in days |
| `archiveRetentionDays` | `number` | No | 365 | S3 archive retention in days |
| `bucketName` | `string` | No | Auto-generated | S3 bucket name |
| `databaseName` | `string` | No | `audit_logs` | Glue database name |

## Outputs

- `bucket`: S3 Bucket for archive storage
- `database`: Glue Database for Athena
- `table`: Glue Table with Parquet schema
- `deliveryStream`: Kinesis Firehose delivery stream

## Querying with Athena

### Example Queries

```sql
-- View all logs from the last 7 days
SELECT * FROM audit_logs.logs
WHERE year = '2024' AND month = '12'
ORDER BY timestamp DESC
LIMIT 100;

-- Count logs by log group
SELECT log_group, COUNT(*) as count
FROM audit_logs.logs
WHERE year = '2024' AND month = '12'
GROUP BY log_group;

-- Search for specific events
SELECT timestamp, message, log_group
FROM audit_logs.logs
WHERE message LIKE '%authentication%'
AND year = '2024' AND month = '12';

-- Find logs for a specific user
SELECT * FROM audit_logs.logs
WHERE user_id = 'user@example.com'
AND year = '2024' AND month = '12'
ORDER BY timestamp DESC;
```

## Schema

| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | bigint | Log timestamp in milliseconds |
| `message` | string | Log message |
| `log_group` | string | CloudWatch log group name |
| `log_stream` | string | CloudWatch log stream name |
| `event_type` | string | Event type (extracted from message) |
| `user_id` | string | User identifier (if available) |
| `ip_address` | string | Client IP address (if available) |

**Partition Keys**: `year`, `month`, `day`

## Cost Optimization

### Storage Costs (per GB/month)
- CloudWatch Logs: $0.50
- S3 Standard: $0.023
- S3 Intelligent-Tiering (90+ days): $0.0125
- S3 Intelligent-Tiering (180+ days): $0.004

### Query Costs
- Athena: $5 per TB scanned
- Parquet reduces scan size by 80-90% vs JSON

### Example Cost (1TB logs/year)
- CloudWatch (30 days): ~$15/month
- S3 Archive (365 days): ~$5-10/month
- Athena queries: ~$0.50 per TB scanned (vs $5 for JSON)

**Total**: ~$20-25/month for 1TB of logs with full year retention

## Best Practices

1. **Use Partitions**: Always filter by year/month/day in queries
2. **Limit Columns**: Select only needed columns to reduce scan size
3. **Batch Queries**: Combine multiple queries to reduce overhead
4. **Monitor Costs**: Use AWS Cost Explorer to track Athena usage
5. **Lifecycle Policies**: Adjust retention based on compliance requirements

## Integration with CloudFront Auth

The `CloudFrontWithAzureAuth` construct automatically creates an `AuditLogArchive` instance for all authentication-related Lambda functions:

- OAuth callback logs
- Secret rotation logs
- Session revocation logs
- Stream processor logs

Access via:
```typescript
const authConstruct = new CloudFrontWithAzureAuth(this, 'Auth', { ... });
const auditBucket = authConstruct.auditLogArchive?.bucket;
```
