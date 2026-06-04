import jwt from "jsonwebtoken";
import redisClient from "../config/redis.js";

const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(" ")[1];

    if (!token) {
      return res.status(401).json({
        error: "Access Token missing",
      });
    }

    // Check Redis blacklist
    const isBlacklisted = await redisClient.get(`blacklist:${token}`);

    if (isBlacklisted) {
      return res.status(403).json({
        error: "Token has been revoked",
      });
    }

    const decodedUser = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

    req.user = decodedUser;

    next();
  } catch (error) {
    return res.status(403).json({
      error: "Token expired or invalid",
    });
  }
};

export default authMiddleware;
