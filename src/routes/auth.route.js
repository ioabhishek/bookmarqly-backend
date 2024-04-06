import { Router } from "express"
import {
  emailPasswordLogin,
  emailPasswordRegister,
  googleLogin,
  googleLoginCallback,
  loginFailed,
  loginSuccess,
  logoutUser,
  refreshAccessToken,
  verifyJwt,
} from "../controllers/auth.controller.js"

const router = Router()

router.post("/register", emailPasswordRegister)
router.get("/google", googleLogin)
router.get("/google/callback", googleLoginCallback)
router.get("/login/success", loginSuccess)
router.get("/login/failed", loginFailed)
router.post("/login", emailPasswordLogin)
router.post("/logout", verifyJwt, logoutUser)
router.post("/refresh-token", refreshAccessToken)

export default router
