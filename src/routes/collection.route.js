import { Router } from "express"
import {
  collectionList,
  createCollection,
  deleteCollection,
  updateCollection,
} from "../controllers/collection.controller.js"
import { verifyJwt } from "../controllers/auth.controller.js"

const router = Router()

router.post("/create_collection", verifyJwt, createCollection)
router.post("/update_collection", verifyJwt, updateCollection)
router.post("/delete_collection", verifyJwt, deleteCollection)
router.get("/explore", collectionList)

export default router
