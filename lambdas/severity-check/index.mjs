import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { ECSClient, RunTaskCommand } from "@aws-sdk/client-ecs";
import { unmarshall } from "@aws-sdk/util-dynamodb";

const dynamo = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const sqs    = new SQSClient({});
const ecs    = new ECSClient({});

export const handler = async (event) => {
  console.log('Severity Check Lambda fired');

  for (const record of event.Records) {
    try {
      if (record.eventName !== 'MODIFY') continue;

      const newImage = unmarshall(record.dynamodb.NewImage);
      const { scanId, status, highCount, repo, prNumber, threshold } = newImage;

      if (status !== 'sast_complete') continue;

      console.log(`Processing severity check for scan ${scanId}`);
      console.log(`HIGH findings: ${highCount}, threshold: ${threshold}`);

      const high  = highCount || 0;
      const limit = threshold || 3;

      if (high >= limit) {
        // Fast block — skip pentest
        console.log(`Fast block — ${high} HIGH findings exceeds threshold of ${limit}`);
        await dynamo.send(new UpdateCommand({
          TableName: process.env.DYNAMODB_TABLE,
          Key: { scanId },
          UpdateExpression: 'SET #s = :s, #os = :os, fastBlock = :fb',
          ExpressionAttributeNames: { '#s': 'status', '#os': 'overall_status' },
          ExpressionAttributeValues: { ':s': 'fast_block', ':os': 'failed', ':fb': true }
        }));
        console.log(`Updated scan ${scanId} to fast_block`);

      } else {
        // Queue pentest and launch Fargate pentest worker
        console.log(`Queuing pentest for scan ${scanId}`);

        await Promise.all([
          sqs.send(new SendMessageCommand({
            QueueUrl:    process.env.PENTEST_QUEUE_URL,
            MessageBody: JSON.stringify({ scanId, repo, prNumber })
          })),
          dynamo.send(new UpdateCommand({
            TableName: process.env.DYNAMODB_TABLE,
            Key: { scanId },
            UpdateExpression: 'SET #s = :s',
            ExpressionAttributeNames: { '#s': 'status' },
            ExpressionAttributeValues: { ':s': 'pentest_queued' }
          }))
        ]);

        // Launch pentest Fargate task
        console.log(`Launching pentest Fargate task for scan ${scanId}`);
        try {
          await ecs.send(new RunTaskCommand({
            cluster:        process.env.ECS_CLUSTER,
            launchType:     'FARGATE',
            taskDefinition: process.env.PENTEST_TASK_DEF,
            networkConfiguration: {
              awsvpcConfiguration: {
                subnets:        [process.env.PRIVATE_SUBNET],
                securityGroups: [process.env.FARGATE_SG],
                assignPublicIp: 'DISABLED'
              }
            }
          }));
          console.log(`Pentest Fargate task launched for scan ${scanId}`);
        } catch (err) {
          console.error(`Failed to launch pentest Fargate task:`, err.message);
        }

        console.log(`Queued pentest and updated status for scan ${scanId}`);
      }
    } catch (err) {
      console.error(`Error processing record:`, err);
      throw err;
    }
  }
};