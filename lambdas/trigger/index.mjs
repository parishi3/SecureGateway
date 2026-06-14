import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand } from "@aws-sdk/lib-dynamodb";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { ECSClient, RunTaskCommand } from "@aws-sdk/client-ecs";

const dynamo = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const sqs = new SQSClient({});
const ecs = new ECSClient({});

export const handler = async (event) => {
  console.log('SecureGate Lambda 1 — trigger fired');
  let body;
  try {
    if (typeof event.body === 'string') {
      body = JSON.parse(event.body);
    } else if (typeof event.body === 'object' && event.body !== null) {
      body = event.body;
    } else {
      body = event;
    }
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  const { imageUri, prNumber, commitSha, repo, repoFullName } = body;
  const repoValue = repo || repoFullName;

  if (!commitSha || !repoValue) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Missing commitSha or repo' }) };
  }

  // SHA cache check — skip duplicate scans
  console.log(`Checking SHA cache for commit: ${commitSha}`);
  const existing = await dynamo.send(new GetCommand({
    TableName: process.env.DYNAMODB_TABLE,
    Key: { scanId: commitSha }
  }));

  if (existing.Item && (existing.Item.overall_status === 'complete' || existing.Item.status === 'complete')) {
    console.log('Cache hit — checking if threshold has changed');
    const config = await dynamo.send(new GetCommand({
      TableName: process.env.CONFIG_TABLE,
      Key: { configKey: 'pentest_skip_threshold' }
    }));
    const currentThreshold = config.Item ? parseInt(config.Item.value) : 3;

    if (existing.Item.threshold === currentThreshold) {
      console.log('Cache hit — returning existing result');
      return {
        statusCode: 200,
        body: JSON.stringify({
          scanId: commitSha,
          status: 'cached',
          message: 'Scan already completed for this commit'
        })
      };
    }
    console.log('Threshold changed — re-evaluating scan');
  }

  // Read severity threshold from config table
  console.log('Reading severity threshold from config table');
  const config = await dynamo.send(new GetCommand({
    TableName: process.env.CONFIG_TABLE,
    Key: { configKey: 'pentest_skip_threshold' }
  }));
  const threshold = config.Item ? parseInt(config.Item.value) : 3;
  console.log(`Severity threshold: ${threshold}`);

  // Write pending record to DynamoDB
  console.log('Writing pending scan record to DynamoDB');
  await dynamo.send(new PutCommand({
    TableName: process.env.DYNAMODB_TABLE,
    Item: {
      scanId: commitSha,
      imageUri: imageUri || 'unknown',
      prNumber: String(prNumber || '0'),
      repo: repoValue,
      status: 'pending',
      threshold,
      timestamp: new Date().toISOString(),
      expiresAt: Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60)
    }
  }));

  // Queue SAST job on SQS
  console.log('Queuing SAST job on SQS');
  await sqs.send(new SendMessageCommand({
    QueueUrl: process.env.SAST_QUEUE_URL,
    MessageBody: JSON.stringify({
      scanId: commitSha,
      imageUri,
      prNumber: String(prNumber || '0'),
      repo: repoValue
    })
  }));

  // Launch SAST Fargate task to process the job
  console.log('Launching SAST Fargate task');
  try {
    await ecs.send(new RunTaskCommand({
      cluster:        process.env.ECS_CLUSTER,
      launchType:     'FARGATE',
      taskDefinition: process.env.SAST_TASK_DEF,
      networkConfiguration: {
        awsvpcConfiguration: {
          subnets:        [process.env.PRIVATE_SUBNET],
          securityGroups: [process.env.FARGATE_SG],
          assignPublicIp: 'DISABLED'
        }
      }
    }));
    console.log('SAST Fargate task launched successfully');
  } catch (err) {
    // Non-fatal — SQS message stays in queue, worker will retry
    console.error('Failed to launch Fargate task:', err.message);
  }

  console.log(`Scan queued successfully for commit ${commitSha}`);
  return {
    statusCode: 200,
    body: JSON.stringify({
      scanId: commitSha,
      status: 'queued',
      message: 'Scan queued successfully'
    })
  };
};
