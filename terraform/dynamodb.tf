# ── SCANS TABLE ──────────────────────────────────────────────────
# Stores one record per scan with status, severity counts, S3 report URL
resource "aws_dynamodb_table" "scans" {
  name         = "${var.project_name}-scans"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "scanId"
  attribute {
    name = "scanId"
    type = "S"
  }
  # Streams enabled — triggers Severity Check Lambda and Results Lambda
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"
  # TTL — auto-delete scan records after 30 days
  ttl {
    attribute_name = "expiresAt"
    enabled        = true
  }
  tags = { Name = "Scans Table" }
}

# ── CONFIG TABLE ─────────────────────────────────────────────────
# Stores platform config — severity threshold, feature flags
# Configurable without redeployment
resource "aws_dynamodb_table" "config" {
  name         = "${var.project_name}-config"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "configKey"
  attribute {
    name = "configKey"
    type = "S"
  }
  tags = { Name = "Config Table" }
}

# ── SEED DEFAULT CONFIG ──────────────────────────────────────────
# Write the default severity threshold to the config table on deploy
resource "aws_dynamodb_table_item" "pentest_threshold" {
  table_name = aws_dynamodb_table.config.name
  hash_key   = aws_dynamodb_table.config.hash_key
  item = jsonencode({
    configKey = { S = "pentest_skip_threshold" }
    value     = { N = tostring(var.pentest_skip_threshold) }
    description = { S = "Number of HIGH severity SAST findings that skips pentest and fast-blocks the PR" }
  })

  lifecycle {
    ignore_changes = all
  }
}
