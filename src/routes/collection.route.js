import { Router } from "express"
import {
  collectionList,
  createCollection,
  deleteCollection,
  updateCollection,
} from "../controllers/collection.controller.js"
import { verifyJwt } from "../controllers/auth.controller.js"

const router = Router()

router.post("/create", verifyJwt, createCollection)
router.post("/update", verifyJwt, updateCollection)
router.post("/delete", verifyJwt, deleteCollection)
router.get("/explore", collectionList)

export default router
