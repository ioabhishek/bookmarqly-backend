import { Router } from "express"
import {
  createCollection,
  deleteCollection,
  exploreCollection,
  myCollection,
  singleCollection,
  updateCollection,
} from "../controllers/collection.controller.js"
import { verifyJwt, verifyUser } from "../controllers/auth.controller.js"

const router = Router()

router.post("/create", verifyJwt, createCollection)
router.post("/update", verifyJwt, updateCollection)
router.post("/delete", verifyJwt, deleteCollection)
router.get("/explore", exploreCollection)
router.get("/my", verifyJwt, myCollection)
router.get("/", verifyUser, myCollection)
router.get("/:collectionId", verifyUser, singleCollection)

export default router
