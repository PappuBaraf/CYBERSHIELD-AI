import IORedis, { RedisOptions } from "ioredis";

export let redisConnection: IORedis | null = null;

function parseRedisUrl(urlStr: string): RedisOptions | null {
  try {
    let cleanUrl = urlStr.trim().replace(/[\n\r"']/g, "");

    const urlMatch = cleanUrl.match(/(rediss?:\/\/[^\s]+)/);
    if (urlMatch) {
      cleanUrl = urlMatch[1];
    }

    if (!cleanUrl.startsWith("redis://") && !cleanUrl.startsWith("rediss://")) {
      console.error("Invalid Redis URL format - must start with redis:// or rediss://");
      return null;
    }

    const url = new URL(cleanUrl);
    const isSecure = url.protocol === "rediss:";
    const isUpstash = url.hostname.includes("upstash.io");

    const options: RedisOptions = {
      host: url.hostname,
      port: parseInt(url.port) || 6379,
      password: url.password || undefined,
      username: url.username || undefined,
      maxRetriesPerRequest: null,
    };

    if (isSecure || isUpstash) {
      options.tls = {
        rejectUnauthorized: false,
      };
      console.log("TLS enabled for connection");
    }

    return options;
  } catch (err: any) {
    console.error("Failed to parse Redis URL:", err.message);
    return null;
  }
}

export async function initRedis(redisUrl: string): Promise<boolean> {
  if (!redisUrl || redisUrl.trim() === "") {
    console.log("No Redis URL provided");
    return false;
  }

  const options = parseRedisUrl(redisUrl);
  if (!options) {
    console.log("Invalid Redis URL");
    return false;
  }

  console.log(`Connecting to Redis: ${options.host}:${options.port} (TLS: ${!!options.tls})`);

  try {
    const connection = new IORedis({
      ...options,
      connectTimeout: 3000,
      lazyConnect: true,
    });

    await Promise.race([
      connection.connect(),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("Redis connection timeout (3s)")), 3000)
      )
    ]);

    console.log("Connected to Redis successfully");
    redisConnection = connection;
    return true;
  } catch (err: any) {
    console.error("Failed to connect to Redis:", err.message);
    return false;
  }
}
