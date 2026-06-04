import { createClient } from "redis";
import dotenv from "dotenv";

dotenv.config();

const redisUrl = `redis://${process.env.REDIS_USER}:${encodeURIComponent(
  process.env.REDIS_PASSWD,
)}@${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`;

const redisClient = createClient({
  url: redisUrl,
});

redisClient.on("error", (err) => {
  console.error("Redis Client Error:", err);
});

await redisClient.connect();

console.log("Connected to Redis server.");

export default redisClient;
