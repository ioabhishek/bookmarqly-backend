import { Router } from "express"
import {
  allBookmarks,
  createBookmark,
  deleteBookmark,
  singleBookmark,
  updateBookmark,
} from "../controllers/bookmark.controller.js"
import { verifyJwt } from "../controllers/auth.controller.js"

const router = Router()

router.get("/", verifyJwt, allBookmarks)
router.post("/create", verifyJwt, createBookmark)
router.post("/update", verifyJwt, updateBookmark)
router.post("/delete", verifyJwt, deleteBookmark)
router.get("/:bookmarkId", verifyJwt, singleBookmark)

export default router
