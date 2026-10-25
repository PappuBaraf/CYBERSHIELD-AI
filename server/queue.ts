import { Queue, Worker, QueueEvents } from "bullmq";
import { performScan } from "./scanService.js";
import { redisConnection } from "./redis.js";

export const QUEUE_NAME = "contract-scan";

export let queue: Queue | null = null;
export let worker: Worker | null = null;
export let queueEvents: QueueEvents | null = null;
export let queueEnabled = false;

export async function initQueue() {
  try {
    const connection = redisConnection;

    if (!connection) {
      console.log("No Redis connection, queue disabled");
      return;
    }

    queue = new Queue(QUEUE_NAME, { connection });
    queueEvents = new QueueEvents(QUEUE_NAME, { connection });

    worker = new Worker(
      QUEUE_NAME,
      async (job) => {
        return await performScan(job.data.address);
      },
      { connection }
    );

    queueEnabled = true;
    console.log("Queue + Worker initialized");
  } catch (err: any) {
    console.error("Queue init failed:", err.message);
    queueEnabled = false;
  }
}

export function isQueueEnabled() {
  return queueEnabled && queue !== null;
}

export async function enqueueScanJob(address: string): Promise<string> {
  if (!queue) throw new Error("Queue not initialized");
  const job = await queue.add("scan", { address });
  return job.id!;
}

export async function getJobStatusDirect(jobId: string) {
  if (!queue) {
    return { status: "failed", error: "Queue not initialized" };
  }

  const job = await queue.getJob(jobId);

  if (!job) {
    return { status: "pending" };
  }

  const state = await job.getState();

  if (state === "completed") {
    return {
      status: "completed",
      result: job.returnvalue,
    };
  }

  if (state === "failed") {
    return {
      status: "failed",
      error: job.failedReason,
    };
  }

  return { status: "pending" };
}

export function getQueue() {
  return queue;
}
