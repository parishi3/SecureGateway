import { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } from "@aws-sdk/client-sqs";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { scanDirectory } from "./scanner.js";
import { execSync } from "child_process";
import { createWriteStream } from "fs";
import { pipeline } from "stream/promises";
import fs from "fs";

const sqs    = new SQSClient({ region: process.env.AWS_REGION || "us-east-1" });
const dynamo = DynamoDBDocumentClient.from(new DynamoDBClient({ region: process.env.AWS_REGION || "us-east-1" }));
const s3     = new S3Client({ region: process.env.AWS_REGION || "us-east-1" });

const QUEUE_URL    = process.env.QUEUE_URL;
const DYNAMO_TABLE = process.env.DYNAMODB_TABLE;
const S3_BUCKET    = process.env.S3_BUCKET;
const MAX_WAIT     = parseInt(process.env.MAX_WAIT_SECONDS || "600");

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

// Download source zip from S3 — Lambda uploaded it there, S3 has VPC endpoint
async function getSourceFromS3(sourceS3Key, scanId) {
  const workDir   = `/tmp/scan-${scanId}`;
  const zipPath   = `${workDir}/repo.zip`;
  const sourceDir = `${workDir}/source`;

  fs.mkdirSync(workDir,   { recursive: true });
  fs.mkdirSync(sourceDir, { recursive: true });

  console.log(`Downloading source zip from S3: ${sourceS3Key}`);

  const response = await s3.send(new GetObjectCommand({
    Bucket: S3_BUCKET,
    Key:    sourceS3Key
  }));

  const writer = createWriteStream(zipPath);
  await pipeline(response.Body, writer);
  console.log(`Downloaded source zip to ${zipPath}`);

  execSync(`unzip -q ${zipPath} -d ${workDir}/extracted`, { timeout: 60000 });

  const extracted = fs.readdirSync(`${workDir}/extracted`)[0];
  execSync(`cp -r ${workDir}/extracted/${extracted}/. ${sourceDir}/`);

  console.log(`Extracted source to ${sourceDir}`);
  return sourceDir;
}

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
    h1 { color: #333; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background: #f4f4f4; }
    tr.high td:first-child { color: #c00; font-weight: bold; }
    tr.medium td:first-child { color: #e65c00; font-weight: bold; }
    tr.low td:first-child { color: #666; }
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

async function uploadReport(scanId, html) {
  await s3.send(new PutObjectCommand({
    Bucket:      S3_BUCKET,
    Key:         `reports/${scanId}.html`,
    Body:        html,
    ContentType: "text/html"
  }));
  console.log(`Report uploaded to s3://${S3_BUCKET}/reports/${scanId}.html`);
}

async function processScan(message) {
  const { scanId, imageUri, repo, sourceS3Key } = JSON.parse(message.Body);
  console.log(`Processing SAST scan for scanId: ${scanId}, repo: ${repo}`);

  if (!repo || repo === "undefined") {
    console.log(`Skipping scan ${scanId} — no valid repo`);
    await updateDynamo(scanId, { status: "sast_complete", highCount: 0, mediumCount: 0, lowCount: 0, sastError: "No repo provided" });
    return;
  }

  if (!sourceS3Key) {
    console.log(`Skipping scan ${scanId} — no sourceS3Key`);
    await updateDynamo(scanId, { status: "sast_complete", highCount: 0, mediumCount: 0, lowCount: 0, sastError: "No source zip available" });
    return;
  }

  await updateDynamo(scanId, { status: "sast_running" });

  let sourceDir;
  try {
    sourceDir = await getSourceFromS3(sourceS3Key, scanId);
  } catch (err) {
    console.error(`Failed to get source from S3:`, err);
    await updateDynamo(scanId, { status: "sast_complete", highCount: 0, mediumCount: 0, lowCount: 0, sastError: err.message });
    return;
  }

  console.log(`Scanning source directory: ${sourceDir}`);
  let vulnerabilities = [];
  try {
    const result = await scanDirectory(sourceDir);
    if (Array.isArray(result)) {
      vulnerabilities = result;
    } else if (result && Array.isArray(result.vulnerabilities)) {
      vulnerabilities = result.vulnerabilities;
    } else {
      console.log(`Scanner returned unexpected format:`, JSON.stringify(result));
    }
  } catch (err) {
    console.error(`Scanner error:`, err);
  }
  const summary = {
    high:   vulnerabilities.filter(v => v.severity === "HIGH").length,
    medium: vulnerabilities.filter(v => v.severity === "MEDIUM").length,
    low:    vulnerabilities.filter(v => v.severity === "LOW").length
  };

  console.log(`Scan complete — HIGH: ${summary.high}, MEDIUM: ${summary.medium}, LOW: ${summary.low}`);

  try {
    const html = generateHtmlReport(scanId, vulnerabilities, summary);
    await uploadReport(scanId, html);
  } catch (err) {
    console.error(`Failed to upload report:`, err);
  }

  await updateDynamo(scanId, {
    status:      "sast_complete",
    highCount:   summary.high,
    mediumCount: summary.medium,
    lowCount:    summary.low
  });

  console.log(`DynamoDB updated — status: sast_complete`);

  try {
    fs.rmSync(`/tmp/scan-${scanId}`, { recursive: true, force: true });
    console.log(`Cleaned up /tmp/scan-${scanId}`);
  } catch (_) {}
}

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
