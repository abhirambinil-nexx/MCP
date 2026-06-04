import db from "../config/db.js";
import redisClient from "../config/redis.js";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import crypto from "crypto";

import { googleClient, client_id } from "../config/google.js";

const DYNAMIC_ACCESS_SECRET = crypto.randomBytes(32).toString("hex");
const DYNAMIC_REFRESH_SECRET = crypto.randomBytes(32).toString("hex");

console.log(
  "🔒 Dynamic cryptographic JWT secret structures initialized in memory.",
);

// Helper function to hash a token
const hashToken = (token) =>
  crypto.createHash("sha256").update(token).digest("hex");

const generateTokens = async (userId) => {
  const accessToken = jwt.sign({ userId }, DYNAMIC_ACCESS_SECRET, {
    expiresIn: "15m",
  });
  const refreshToken = jwt.sign({ userId }, DYNAMIC_REFRESH_SECRET, {
    expiresIn: "30d",
  });
  return { accessToken, refreshToken };
};

export const googleAuth = async (req, res) => {
  // mode parameter passed from the frontend to manage explicit flows if necessary
  const { idToken, mode } = req.body;
  if (!idToken) return res.status(400).json({ error: "ID Token missing" });

  try {
    // Uses modular credential initialization directly from JSON schema file layout
    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: client_id,
    });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    let userId;
    const [oauthAccounts] = await db.execute(
      'SELECT user_id FROM oauth_accounts WHERE provider = "google" AND provider_user_id = ?',
      [googleId],
    );

    if (oauthAccounts.length > 0) {
      if (mode === "signup") {
        return res
          .status(400)
          .json({ error: "Account already exists. Please Sign In instead." });
      }
      userId = oauthAccounts[0].user_id;
    } else {
      if (mode === "login") {
        return res.status(404).json({
          error:
            "No account found with this Google profile. Please Sign Up first.",
        });
      }

      // Check if user email exists but isn't linked
      const [users] = await db.execute("SELECT id FROM users WHERE email = ?", [
        email,
      ]);
      if (users.length > 0) {
        userId = users[0].id;
      } else {
        // Completely new user account creation
        userId = uuidv4();
        const username = email.split("@")[0] + Math.floor(Math.random() * 1000);
        await db.execute(
          "INSERT INTO users (id, email, name, username, profile_picture, email_verified) VALUES (?, ?, ?, ?, ?, true)",
          [userId, email, name, username, picture],
        );
      }
      // Add mapping entry to oauth_accounts
      await db.execute(
        'INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, provider_email) VALUES (?, ?, "google", ?, ?)',
        [uuidv4(), userId, googleId, email],
      );
    }

    const { accessToken, refreshToken } = await generateTokens(userId);
    const hashedRefresh = hashToken(refreshToken);
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    await db.execute(
      "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
      [
        uuidv4(),
        userId,
        hashedRefresh,
        expiresAt,
        req.ip,
        req.headers["user-agent"],
      ],
    );

    // Cache updated user information container inside Redis memory cluster
    const [freshUserObj] = await db.execute(
      "SELECT * FROM users WHERE id = ?",
      [userId],
    );
    if (freshUserObj.length > 0) {
      await redisClient.setEx(
        `userprofile:${name}${userId}`,
        3600,
        JSON.stringify(freshUserObj[0]),
      );
    }

    res.json({ accessToken, refreshToken });
  } catch (err) {
    res
      .status(401)
      .json({ error: "Google Verification Failed: " + err.message });
  }
};

export const refresh = async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken)
    return res.status(400).json({ error: "Refresh token missing" });

  try {
    // Verified against the runtime generated dynamic secret instance
    const decoded = jwt.verify(refreshToken, DYNAMIC_REFRESH_SECRET);
    const hashedRefresh = hashToken(refreshToken);

    const [tokens] = await db.execute(
      "SELECT * FROM refresh_tokens WHERE token_hash = ? AND revoked_at IS NULL",
      [hashedRefresh],
    );
    if (tokens.length === 0)
      return res
        .status(403)
        .json({ error: "Invalid or revoked refresh token" });

    const tokenRow = tokens[0];
    if (new Date() > new Date(tokenRow.expires_at))
      return res.status(403).json({ error: "Refresh token expired" });

    // Token Rotation: Revoke existing token row
    await db.execute(
      "UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = ?",
      [tokenRow.id],
    );

    // Generate brand new updated pair
    const newTokens = await generateTokens(decoded.userId);
    const newHashedRefresh = hashToken(newTokens.refreshToken);
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    await db.execute(
      "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
      [
        uuidv4(),
        decoded.userId,
        newHashedRefresh,
        expiresAt,
        req.ip,
        req.headers["user-agent"],
      ],
    );

    res.json({
      accessToken: newTokens.accessToken,
      refreshToken: newTokens.refreshToken,
    });
  } catch (err) {
    res.status(403).json({ error: "Invalid token structure" });
  }
};

export const logout = async (req, res) => {
  const { refreshToken } = req.body;
  const authHeader = req.headers["authorization"];
  const accessToken = authHeader && authHeader.split(" ")[1];

  try {
    if (refreshToken) {
      const hashedRefresh = hashToken(refreshToken);
      await db.execute(
        "UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = ?",
        [hashedRefresh],
      );
    }
    if (accessToken) {
      // Blacklist short-lived access token in Redis until it naturally expires anyway (15m = 900s)
      await redisClient.setEx(`blacklist:${accessToken}`, 900, "true");
    }
    res.json({ message: "Logged out successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

export const getProfile = async (req, res) => {
  try {
    // Try getting profile data straight from optimized Redis cache first
    const cachedUser = await redisClient.get(`userprofile:${req.user.name}${req.user.userId}`);
    if (cachedUser)
      return res.json({ source: "cache", data: JSON.parse(cachedUser) });

    const [users] = await db.execute(
      "SELECT id, email, name, username, profile_picture FROM users WHERE id = ?",
      [req.user.userId],
    );
    if (users.length === 0)
      return res.status(404).json({ error: "User not found" });

    await redisClient.setEx(
      `userprofile:${req.user.name}${req.user.userId}`,
      3600,
      JSON.stringify(users[0]),
    );
    res.json({ source: "database", data: users[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
