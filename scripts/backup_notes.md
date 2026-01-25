# Backup / Disaster Recovery notes

Your durable truth is:
- Aurora cluster (identity + memory + policy)
- Artifact bucket (S3)
- Audit bucket (S3 Object Lock)

## Practical backup strategy

1) **Aurora snapshot** (point-in-time restore)

```bash
aws rds create-db-cluster-snapshot \
  --db-cluster-identifier <cluster-id> \
  --db-cluster-snapshot-identifier <name>
```

2) **Export snapshot to S3** (portable)

Aurora supports exporting snapshots to S3 in Parquet for long-term retention.
From there you can download or replicate.

3) **Replicate buckets**

- Enable cross-region replication if you want another AWS Region.
- Also `aws s3 sync` to local disk for cold storage.

4) **Restore in another cloud / on-prem**

- Restore export into a local Postgres instance (and re-enable pgvector).
- Replay audit log objects if you need to verify integrity.
