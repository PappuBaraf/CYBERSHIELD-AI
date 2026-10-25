import "dotenv/config";
import { v4 as uuidv4 } from "uuid";
import { createBullBoard } from "@bull-board/api";
import { BullMQAdapter } from "@bull-board/api/bullMQAdapter";
import { ExpressAdapter } from "@bull-board/express";
import { initQueue, getQueue } from "./queue.js";
import { initRedis } from "./redis.js";
import { createApp } from "./app.js";

const PORT = Number(process.env.PORT) || 3001;
const HOST = process.env.HOST || "127.0.0.1";

async function main() {
  const { app } = createApp();
  const redisUrl = process.env.REDIS_URL || process.env.UPSTASH_REDIS_URL || null;

  if (redisUrl) {
    console.log("Initializing Redis...");
    if (await initRedis(redisUrl)) await initQueue();

    const queue = getQueue();
    // Bull Board admin UI: development only (incompatible with Express 5 in production)
    if (queue && process.env.NODE_ENV !== "production") {
      const serverAdapter = new ExpressAdapter();
      serverAdapter.setBasePath("/admin/queues");
      createBullBoard({ queues: [new BullMQAdapter(queue)], serverAdapter });
      const ADMIN_USER = process.env.ADMIN_USER || "admin";
      const ADMIN_PASS = process.env.ADMIN_PASS || uuidv4();
      app.use(
        "/admin/queues",
        (req, res, next) => {
          const auth = req.headers.authorization;
          if (auth?.startsWith("Basic ")) {
            const [user, ...rest] = Buffer.from(auth.slice(6), "base64").toString().split(":");
            if (user === ADMIN_USER && rest.join(":") === ADMIN_PASS) return next();
          }
          res.setHeader("WWW-Authenticate", 'Basic realm="Bull Board Admin"');
          res.status(401).send("Authentication required");
        },
        serverAdapter.getRouter()
      );
      console.log(
        `Bull Board at /admin/queues (user: ${ADMIN_USER}, pass: ${process.env.ADMIN_PASS ? "from ADMIN_PASS" : ADMIN_PASS})`
      );
    }
  } else {
    console.log("No REDIS_URL set. Running in direct mode (no queue).");
  }

  app.listen(PORT, HOST, () => {
    console.log(`ContractScan server listening on http://${HOST}:${PORT}`);
  });
}

main().catch((err) => {
  console.error("Fatal server error:", err);
  process.exit(1);
});
