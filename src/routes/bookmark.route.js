import { Router } from "express"
import {
  allBookmarks,
  createBookmark,
  deleteBookmark,
  updateBookmark,
} from "../controllers/bookmark.controller.js"
import { verifyJwt } from "../controllers/auth.controller.js"

const router = Router()

router.get("/", verifyJwt, allBookmarks)
router.post("/create", verifyJwt, createBookmark)
router.patch("/update", verifyJwt, updateBookmark)
router.delete("/delete", verifyJwt, deleteBookmark)

export default router
