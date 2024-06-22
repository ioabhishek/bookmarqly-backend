import prisma from "../DB/db.config.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import { ErrorResponse } from "../utils/ErrorResponse.js"

export const createCollection = async (req, res) => {
  const { title, description, thumbnail, isPublic } = req.body

  const user = await prisma.user.findUnique({
    where: {
      id: req.user.id,
    },
  })

  if (!user) {
    return res.status(201).json(new ErrorResponse(404, "User does not exist"))
  }

  const collection = await prisma.collection.create({
    data: {
      title: title,
      description: description,
      thumbnail: thumbnail,
      isPublic: isPublic,
      userId: req.user.id,
    },
  })

  return res
    .status(201)
    .json(
      new ApiResponse(
        201,
        { collection: collection },
        "Collection created successfully"
      )
    )
}

export const updateCollection = async (req, res) => {
  const { id, title, description, thumbnail, isPublic } = req.body

  const isCollection = await prisma.collection.findUnique({
    where: {
      id: id,
      // userId: req.user.id,
    },
  })

  if (!isCollection) {
    return res.status(404).json(new ErrorResponse(404, "No Collection found"))
  }

  if (isCollection?.userId !== req.user.id) {
    return res
      .status(403)
      .json(
        new ErrorResponse(
          403,
          "You are not authorized to update this collection"
        )
      )
  }

  const collection = await prisma.collection.update({
    where: {
      id: id,
    },
    data: {
      title: title,
      description: description,
      thumbnail: thumbnail,
      isPublic: isPublic,
    },
  })

  return res
    .status(201)
    .json(
      new ApiResponse(
        201,
        { collection: collection },
        "Collection updated successfully"
      )
    )
}

export const deleteCollection = async (req, res) => {
  const { id } = req.body

  const isCollection = await prisma.collection.findUnique({
    where: {
      id: id,
    },
  })

  if (!isCollection) {
    return res.status(404).json(new ErrorResponse(404, "No collection found"))
  }

  if (isCollection?.userId !== req.user.id) {
    return res
      .status(403)
      .json(
        new ErrorResponse(
          403,
          "You are not authorized to delete this collection"
        )
      )
  }

  await prisma.collection.delete({
    where: {
      id: id,
    },
  })

  return res
    .status(201)
    .json(new ApiResponse(201, {}, "Collection deleted successfully"))
}

export const collectionList = async (req, res) => {
  const collection = await prisma.collection.findMany({
    where: {
      isPublic: true,
    },
    select: {
      id: true,
      title: true,
      description: true,
      thumbnail: true,
      isPublic: true,
      user: {
        select: {
          id: true,
          name: true,
          username: true,
        },
      },
    },
  })

  return res
    .status(201)
    .json(
      new ApiResponse(
        201,
        { collection: collection },
        "Collection list Fetched successfully"
      )
    )
}
