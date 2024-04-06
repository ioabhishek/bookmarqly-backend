import { Router } from "express"
import {
  googleLogin,
  googleLoginCallback,
  loginFailed,
  loginSuccess,
  logoutUser,
  verifyJwt,
} from "../controllers/auth.controller.js"

const router = Router()

router.get("/google", googleLogin)
router.get("/google/callback", googleLoginCallback)
router.get("/login/success", loginSuccess)
router.get("/login/failed", loginFailed)
router.post("/logout", verifyJwt, logoutUser)

export default router
