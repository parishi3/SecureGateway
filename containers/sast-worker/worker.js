import { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } from "@aws-sdk/client-sqs";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { scanDirectory } from "./scanner.js";
import { execSync } from "child_process";
import fs from "fs";

const sqs    = new SQSClient({ region: process.env.AWS_REGION || "us-east-1" });
const dynamo = DynamoDBDocumentClient.from(new DynamoDBClient({ region: process.env.AWS_REGION || "us-east-1" }));
const s3     = new S3Client({ region: process.env.AWS_REGION || "us-east-1" });

const QUEUE_URL    = process.env.QUEUE_URL;
const DYNAMO_TABLE = process.env.DYNAMODB_TABLE;
const S3_BUCKET    = process.env.S3_BUCKET;
const MAX_WAIT     = parseInt(process.env.MAX_WAIT_SECONDS || "600");

// ── POLL SQS ─────────────────────────────────────────────────────

async function pollQueue() {
  const result = await sqs.send(new ReceiveMessageCommand({
    QueueUrl:            QUEUE_URL,
    MaxNumberOfMessages: 1,
    WaitTimeSeconds:     20,
    VisibilityTimeout:   600
  }));
  return result.Messages?.[0] || null;
}

async function deleteMessage(receiptHandle) {
  await sqs.send(new DeleteMessageCommand({
    QueueUrl:      QUEUE_URL,
    ReceiptHandle: receiptHandle
  }));
}

// ── CLONE REPO AND GET SOURCE ─────────────────────────────────────
// Fargate containers don't have Docker — clone the repo directly instead

async function cloneRepo(repo, commitSha, scanId) {
  const workDir = `/tmp/scan-${scanId}`;
  const sourceDir = `${workDir}/source`;
  fs.mkdirSync(workDir, { recursive: true });

  console.log(`Cloning repo: https://github.com/${repo}.git at commit ${commitSha}`);
  execSync(
    `git clone --depth 1 https://github.com/${repo}.git ${sourceDir}`,
    { stdio: "inherit", timeout: 120000 }
  );

  // Checkout the specific commit if needed
  try {
    execSync(`cd ${sourceDir} && git fetch --depth 1 origin ${commitSha} && git checkout ${commitSha}`, {
      stdio: "inherit",
      timeout: 60000
    });
  } catch (_) {
    // If specific commit checkout fails, use whatever was cloned (latest)
    console.log(`Could not checkout specific commit — scanning latest`);
  }

  return sourceDir;
}

// ── UPDATE DYNAMODB ───────────────────────────────────────────────

async function updateDynamo(scanId, fields) {
  const setExpressions = [];
  const names  = {};
  const values = {};

  for (const [key, val] of Object.entries(fields)) {
    setExpressions.push(`#${key} = :${key}`);
    names[`#${key}`]  = key;
    values[`:${key}`] = val;
  }

  await dynamo.send(new UpdateCommand({
    TableName:                 DYNAMO_TABLE,
    Key:                       { scanId },
    UpdateExpression:          `SET ${setExpressions.join(", ")}`,
    ExpressionAttributeNames:  names,
    ExpressionAttributeValues: values
  }));
}

// ── GENERATE HTML REPORT ─────────────────────────────────────────

function generateHtmlReport(scanId, vulnerabilities, summary) {
  const rows = vulnerabilities.map(v => `
    <tr class="${v.severity.toLowerCase()}">
      <td>${v.severity}</td>
      <td>${v.name}</td>
      <td>${v.file || "—"}:${v.line || "—"}</td>
      <td><code>${(v.evidence || "").replace(/</g, "&lt;")}</code></td>
      <td>${v.message}</td>
    </tr>`).join("");

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>SecureGate SAST Report — ${scanId}</title>
  <style>
    body { font-family: sans-serif; padding: 2rem; }
    h1   { color: #333; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background: #f4f4f4; }
    tr.high   td:first-child { color: #c00; font-weight: bold; }
    tr.medium td:first-child { color: #e65c00; font-weight: bold; }
    tr.low    td:first-child { color: #666; }
    .summary { margin-bottom: 1.5rem; }
    code { background: #f0f0f0; padding: 2px 4px; border-radius: 3px; font-size: 0.85em; }
  </style>
</head>
<body>
  <h1>🔒 SecureGate SAST Report</h1>
  <div class="summary">
    <p><strong>Scan ID:</strong> ${scanId}</p>
    <p><strong>Scanned at:</strong> ${new Date().toISOString()}</p>
    <p><strong>HIGH:</strong> ${summary.high} &nbsp;
       <strong>MEDIUM:</strong> ${summary.medium} &nbsp;
       <strong>LOW:</strong> ${summary.low}</p>
  </div>
  <table>
    <thead>
      <tr><th>Severity</th><th>Issue</th><th>Location</th><th>Evidence</th><th>Message</th></tr>
    </thead>
    <tbody>${rows || "<tr><td colspan='5'>No vulnerabilities found</td></tr>"}</tbody>
  </table>
</body>
</html>`;
}

// ── UPLOAD REPORT TO S3 ───────────────────────────────────────────

async function uploadReport(scanId, html) {
  await s3.send(new PutObjectCommand({
    Bucket:      S3_BUCKET,
    Key:         `reports/${scanId}.html`,
    Body:        html,
    ContentType: "text/html"
  }));
  console.log(`Report uploaded to s3://${S3_BUCKET}/reports/${scanId}.html`);
}

// ── PROCESS ONE SCAN JOB ─────────────────────────────────────────

async function processScan(message) {
  const { scanId, imageUri, repo } = JSON.parse(message.Body);

  // Extract commitSha from imageUri tag (format: .../client-scans:<commitSha>)
  const commitSha = imageUri?.split(":").pop() || scanId;

  console.log(`Processing SAST scan for scanId: ${scanId}, repo: ${repo}`);

  // Skip invalid messages from old test runs
  if (!repo || repo === "undefined") {
    console.log(`Skipping scan ${scanId} — no valid repo`);
    await updateDynamo(scanId, {
      status:      "sast_complete",
      highCount:   0,
      mediumCount: 0,
      lowCount:    0,
      sastError:   "No repo provided"
    });
    return;
  }

  // Mark as running
  await updateDynamo(scanId, { status: "sast_running" });

  let sourceDir;
  try {
    sourceDir = await cloneRepo(repo, commitSha, scanId);
  } catch (err) {
    console.error(`Failed to clone repo:`, err);
    await updateDynamo(scanId, {
      status:      "sast_complete",
      highCount:   0,
      mediumCount: 0,
      lowCount:    0,
      sastError:   err.message
    });
    return;
  }

  // Run the scanner
  console.log(`Scanning source directory: ${sourceDir}`);
  let vulnerabilities = [];
  try {
    vulnerabilities = await scanDirectory(sourceDir);
  } catch (err) {
    console.error(`Scanner error:`, err);
  }

  const summary = {
    high:   vulnerabilities.filter(v => v.severity === "HIGH").length,
    medium: vulnerabilities.filter(v => v.severity === "MEDIUM").length,
    low:    vulnerabilities.filter(v => v.severity === "LOW").length
  };

  console.log(`Scan complete — HIGH: ${summary.high}, MEDIUM: ${summary.medium}, LOW: ${summary.low}`);

  // Upload HTML report
  try {
    const html = generateHtmlReport(scanId, vulnerabilities, summary);
    await uploadReport(scanId, html);
  } catch (err) {
    console.error(`Failed to upload report:`, err);
  }

  // Write results to DynamoDB — status = "sast_complete" triggers Severity Check Lambda
  await updateDynamo(scanId, {
    status:      "sast_complete",
    highCount:   summary.high,
    mediumCount: summary.medium,
    lowCount:    summary.low
  });

  console.log(`DynamoDB updated — status: sast_complete`);

  // Cleanup
  try {
    fs.rmSync(`/tmp/scan-${scanId}`, { recursive: true, force: true });
    console.log(`Cleaned up /tmp/scan-${scanId}`);
  } catch (_) {}
}

// ── MAIN LOOP ────────────────────────────────────────────────────

async function main() {
  console.log("SAST worker started — polling SQS...");
  console.log(`Queue: ${QUEUE_URL}`);
  console.log(`Table: ${DYNAMO_TABLE}`);
  console.log(`Bucket: ${S3_BUCKET}`);

  const startTime = Date.now();

  while (true) {
    if ((Date.now() - startTime) / 1000 > MAX_WAIT) {
      console.log(`Max wait time (${MAX_WAIT}s) reached — exiting`);
      process.exit(0);
    }

    let message;
    try {
      message = await pollQueue();
    } catch (err) {
      console.error("SQS poll error:", err);
      await new Promise(r => setTimeout(r, 5000));
      continue;
    }

    if (!message) {
      console.log("No messages — waiting...");
      continue;
    }

    try {
      await processScan(message);
      await deleteMessage(message.ReceiptHandle);
      console.log("Message deleted from queue");
    } catch (err) {
      console.error("Failed to process scan — message will return to queue for retry:", err);
    }
  }
}

main().catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});
