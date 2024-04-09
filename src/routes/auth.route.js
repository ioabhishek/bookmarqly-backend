import { Router } from "express"
import {
  emailPasswordLogin,
  googleLogin,
  googleLoginCallback,
  loginFailed,
  loginSuccess,
  logoutUser,
  refreshAccessToken,
  registerUser,
  verifyEmail,
  verifyJwt,
} from "../controllers/auth.controller.js"

const router = Router()

router.get("/google", googleLogin)
router.get("/google/callback", googleLoginCallback)
router.get("/login/success", loginSuccess)
router.get("/login/failed", loginFailed)
router.post("/login", emailPasswordLogin)
router.post("/logout", verifyJwt, logoutUser)
router.post("/refresh-token", refreshAccessToken)
router.post("/register", registerUser)
router.get("/users/verify-email/:verificationToken", verifyEmail)

// router.post("/fogot-password", resetForgottenPassword)
// router.post("/change-password", changeCurrentPassword)
// router.post("/update-user", updateUserDetsils)

export default router
