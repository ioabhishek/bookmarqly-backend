import { z } from "zod"
import ogs from "open-graph-scraper"
import prisma from "../DB/db.config.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import { ErrorResponse } from "../utils/ErrorResponse.js"
import { createBookmarkSchema, updateBookmarkSchema } from "../validations.js"

export const allBookmarks = async (req, res) => {
  const bookmarks = await prisma.bookmark.findMany({
    where: {
      userId: req.user.id,
    },
  })

  return res
    .status(201)
    .json(new ApiResponse(201, bookmarks, "Bookmarks fetched successfully"))
}

export const createBookmark = async (req, res) => {
  const validationResult = createBookmarkSchema.safeParse(req.body)

  if (!validationResult.success) {
    const errors = validationResult.error.errors.map((err) => ({
      path: err.path.join("."),
      message: err.message,
    }))
    return res
      .status(400)
      .json(new ApiResponse(400, { errors }, "Validation error"))
  }

  const { title, url, note, collectionId } = validationResult.data

  const collection = await prisma.collection.findUnique({
    where: {
      id: collectionId,
    },
  })

  if (!collection) {
    return res
      .status(404)
      .json(new ErrorResponse(404, "Please create/select a collection"))
  }

  const options = { url }
  let ogImage, ogTitle, ogDescription

  try {
    const { result } = await ogs(options)
    ogImage = result?.ogImage[0]?.url
    ogTitle = result?.ogTitle
    ogDescription = result?.ogDescription
  } catch (error) {
    console.error("Error fetching Open Graph data:", error)
  }

  const bookmark = await prisma.bookmark.create({
    data: {
      title: title,
      url: url,
      note: note,
      collectionId: collectionId,
      userId: req.user.id,
      ogImage: ogImage,
      ogTitle: ogTitle,
      ogDescription: ogDescription,
    },
  })

  return res
    .status(201)
    .json(new ApiResponse(201, bookmark, "Bookmark created successfully"))
}

export const updateBookmark = async (req, res) => {
  const validationResult = updateBookmarkSchema.safeParse(req.body)

  if (!validationResult.success) {
    const errors = validationResult.error.errors.map((err) => ({
      path: err.path.join("."),
      message: err.message,
    }))
    return res
      .status(400)
      .json(new ApiResponse(400, { errors }, "Validation error"))
  }

  const { title, url, note, bookmarkId } = validationResult.data

  const bookmark = await prisma.bookmark.findUnique({
    where: {
      id: bookmarkId,
    },
  })

  if (!bookmark) {
    return res.status(404).json(new ErrorResponse(404, "No bookmark found"))
  }

  const updatedBookmark = await prisma.bookmark.update({
    where: {
      id: bookmarkId,
    },
    data: {
      title: title,
      url: url,
      note: note,
    },
  })

  return res
    .status(201)
    .json(
      new ApiResponse(201, { updatedBookmark }, "Bookmark updated successfully")
    )
}

export const deleteBookmark = async (req, res) => {
  const { bookmarkId } = req.body

  const bookmark = await prisma.bookmark.findUnique({
    where: {
      id: bookmarkId,
    },
  })

  if (!bookmark) {
    return res.status(404).json(new ErrorResponse(404, "No bookmark found"))
  }

  if (bookmark?.userId !== req.user.id) {
    return res
      .status(403)
      .json(
        new ErrorResponse(403, "You are not authorized to delete this bookmark")
      )
  }

  await prisma.bookmark.delete({
    where: {
      id: bookmarkId,
    },
  })

  return res
    .status(201)
    .json(new ErrorResponse(201, "Bookmark deleted successfully"))
}

export const singleBookmark = async (req, res) => {
  const { bookmarkId } = req.params
  const bookmark = await prisma.bookmark.findUnique({
    where: {
      id: bookmarkId,
    },
  })

  if (!bookmark) {
    return res.status(404).json(new ErrorResponse(404, "No Bookmark found"))
  }

  return res
    .status(201)
    .json(new ApiResponse(201, bookmark, "Bookmark fetched successfully"))
}
