import redisClient from "../config/redis.js";

const rateLimiter = async (req, res, next) => {
  const ip = req.ip;
  const key = `ratelimit:${ip}`;

  try {
    const requests = await redisClient.incr(key);

    if (requests === 1) {
      await redisClient.expire(key, 60); 
    }

    if (requests > 60) {
      return res.status(429).json({
        error: "Too many requests. Slow down.",
      });
    }

    next();
  } catch (error) {
    next();
  }
};

export default rateLimiter;
