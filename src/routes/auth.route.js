import { Router } from "express"
import {
  changeCurrentPassword,
  forgotPasswordRequest,
  googleLogin,
  googleLoginCallback,
  loginFailed,
  loginSuccess,
  loginUser,
  logoutUser,
  refreshAccessToken,
  registerUser,
  resendEmailVerification,
  resetForgottenPassword,
  verifyEmail,
  verifyJwt,
} from "../controllers/auth.controller.js"

const router = Router()

router.get("/google", googleLogin)
router.get("/google/callback", googleLoginCallback)
router.get("/login/success", loginSuccess)
router.get("/login/failed", loginFailed)
router.post("/refresh-token", refreshAccessToken)
router.post("/register", registerUser)
router.post("/login", loginUser)
router.post("/logout", verifyJwt, logoutUser)
router.get("/users/verify-email/:verificationToken", verifyEmail)
router.post("/resend-email-verification", resendEmailVerification)
router.post("/forgot-password", forgotPasswordRequest)
router.post("/users/reset-password/:resetToken", resetForgottenPassword)
router.post("/change-password", verifyJwt, changeCurrentPassword)

export default router
