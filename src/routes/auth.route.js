import { Router } from "express"
import {
  googleLogin,
  googleLoginCallback,
  loginFailed,
  loginSuccess,
} from "../controllers/auth.controller.js"

const router = Router()

router.get("/google", googleLogin)
router.get("/google/callback", googleLoginCallback)
router.get("/login/success", loginSuccess)
router.get("/login/failed", loginFailed)

export default router
