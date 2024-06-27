import prisma from "../DB/db.config.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import { ErrorResponse } from "../utils/ErrorResponse.js"
import {
  createCollectionSchema,
  updateCollectionSchema,
} from "../validations.js"

export const createCollection = async (req, res) => {
  const validationResult = createCollectionSchema.safeParse(req.body)

  if (!validationResult.success) {
    const errors = validationResult.error.errors.map((err) => ({
      path: err.path.join("."),
      message: err.message,
    }))
    return res
      .status(400)
      .json(new ApiResponse(400, { errors }, "Validation error"))
  }

  const { title, description, thumbnail, isPublic } = validationResult.data

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
  const validationResult = updateCollectionSchema.safeParse(req.body)

  if (!validationResult.success) {
    const errors = validationResult.error.errors.map((err) => ({
      path: err.path.join("."),
      message: err.message,
    }))
    return res
      .status(400)
      .json(new ApiResponse(400, { errors }, "Validation error"))
  }

  const { title, description, thumbnail, isPublic, collectionId } =
    validationResult.data

  const isCollection = await prisma.collection.findUnique({
    where: {
      id: collectionId,
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
      id: collectionId,
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

export const myCollection = async (req, res) => {
  const collection = await prisma.collection.findMany({
    where: {
      userId: req.user.id,
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

export const exploreCollection = async (req, res) => {
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

export const singleCollection = async (req, res, next) => {
  const { collectionId } = req.params
  const collection = await prisma.collection.findUnique({
    where: {
      id: collectionId,
    },
    select: {
      id: true,
      title: true,
      description: true,
      thumbnail: true,
      isPublic: true,
      userId: true,
      user: {
        select: {
          id: true,
          name: true,
          username: true,
        },
      },
      Bookmark: {
        select: {
          id: true,
          title: true,
          url: true,
          note: true,
        },
      },
    },
  })

  if (!collection) {
    return res.status(404).json(new ErrorResponse(404, "No Collection found"))
  }

  if (collection?.isPublic) {
    return res
      .status(201)
      .json(new ApiResponse(201, collection, "Collection fetched successfully"))
  } else {
    if (collection?.userId === req.user.id) {
      return res
        .status(201)
        .json(
          new ApiResponse(201, collection, "Collection fetched successfully")
        )
    } else {
      return res
        .status(403)
        .json(
          new ErrorResponse(
            403,
            "You are not authorized to view this collection"
          )
        )
    }
  }
}
