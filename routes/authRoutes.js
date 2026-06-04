import express from "express";
import * as authController from "../controllers/authController.js";
import verifyToken from "../middleware/auth.js";
import rateLimiter from "../middleware/rateLimiter.js";

const router = express.Router();


router.post("/google", rateLimiter, authController.googleAuth);

router.post("/refresh", authController.refresh);
router.post("/logout", authController.logout);

router.get("/profile", verifyToken, authController.getProfile);

export default router;