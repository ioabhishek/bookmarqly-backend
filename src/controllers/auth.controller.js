import passport from "passport"
import prisma from "../DB/db.config.js"
import ApiError from "../utils/ApiError.js"
import jwt from "jsonwebtoken"
import bcrypt from "bcryptjs"
import { ApiResponse } from "../utils/ApiResponse.js"

const generateAccessTokenAndRefreshToken = async (id) => {
  try {
    // Find user by id
    const user = await prisma.user.findUnique({
      where: {
        id: id,
      },
    })

    // Generate access token
    const accessToken = jwt.sign(
      {
        id: user.id,
        email: user.email,
        username: user.username,
        picture: user.picture,
        isEmailVerified: user.isEmailVerified,
        loginType: user.loginType,
      },
      process.env.ACCESS_TOKEN_SECRET,
      {
        expiresIn: "24h",
      }
    )

    // Generate access token
    const refreshToken = jwt.sign(
      {
        id: user.id,
      },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "1w" }
    )

    // Once Refresh Token is available update user refresh token
    await prisma.user.update({
      where: {
        id: user.id,
      },
      data: {
        refreshToken: refreshToken,
      },
    })

    return { accessToken, refreshToken }
  } catch (error) {
    throw ApiError(
      500,
      "Something went wrong while generating the refresh token"
    )
  }
}

const handleSocialLogin = async (req, res) => {
  const user = await prisma.user.findUnique({
    where: {
      id: req.user.id,
    },
  })

  if (!user) {
    throw ApiError(404, "User does not exist")
  }

  const { accessToken, refreshToken } =
    await generateAccessTokenAndRefreshToken(user.id)

  const options = {
    httpOnly: true,
    secure: false,
  }

  return res
    .status(301)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .redirect("http://localhost:3000/ioabhishek")
}

export const logoutUser = async (req, res) => {
  await prisma.user.update({
    where: {
      id: req.user.id,
    },
    data: {
      refreshToken: undefined,
    },
  })

  const options = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
  }

  return res
    .status(200)
    .clearCookie("accesstoken", options)
    .clearCookie("refreshtoken", options)
    .json(new ApiResponse(200, {}, "User logged out"))
}

export const googleLogin = (req, res, next) => {
  passport.authenticate("google", { scope: ["profile", "email"] })(
    req,
    res,
    next
  )
}

export const googleLoginCallback = (req, res, next) => {
  passport.authenticate("google", {
    failureRedirect: "/login/failed",
    session: false,
  })(req, res, async () => {
    await handleSocialLogin(req, res)
  })
}

export const loginSuccess = (req, res) => {
  if (req.user) {
    res.status(200).json({
      success: true,
      user: req.user,
      cookies: req.cookies,
    })
  }
}

export const loginFailed = (req, res) => {
  res.status(401).json({
    success: false,
    message: "failure",
  })
}

export const verifyJwt = async (req, res, next) => {
  // Get token form Cookies or Authorization Header
  const token =
    req.cookies.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "")

  // If no token then return Error
  if (!token) {
    throw ApiError(401, "Unauthorized request")
  }

  try {
    // Decode the token
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)

    // Using id from the decoded token find user in Database
    const user = await prisma.user.findUnique({
      where: {
        id: decodedToken.id,
      },
      select: {
        id: true,
        email: true,
        username: true,
        picture: true,
        isEmailVerified: true,
        loginType: true,
      },
    })

    // Check if user is valid or not & throw error if not
    if (!user) {
      throw ApiError(401, "Invalid access token")
    }

    req.user = user
    next()
  } catch (error) {
    throw ApiError(401, error?.message || "Invalid access token")
  }
}

export const refreshAccessToken = async (req, res, next) => {
  const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

  if (!incomingRefreshToken) {
    throw ApiError(401, "Unauthorized request")
    // res.status(401).json({ message: "Unauthorized request" })
  }

  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    )

    const user = await prisma.user.findUnique({
      where: {
        id: decodedToken.id,
      },
    })

    if (!user) {
      throw ApiError(401, "Invalid refresh token")
    }

    // check if incoming refresh token is same as the refresh token attached in the user document
    // This shows that the refresh token is used or not
    // Once it is used, we are replacing it with new refresh token below

    if (incomingRefreshToken !== user?.refreshToken) {
      return next(ApiError(401, "Refresh token is expired or used"))
    }

    const options = {
      httpOnly: true,
      secure: process.env.NODE_ENV !== "production",
    }

    const { accessToken, refreshToken: newRefreshToken } =
      await generateAccessTokenAndRefreshToken(user?.id)

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access token refreshed"
        )
      )
  } catch (error) {
    throw ApiError(401, error?.message || "Invalid refresh token")
  }
}

export const emailPasswordLogin = (req, res, next) => {
  passport.authenticate("local", { session: false })(
    req,
    res,
    async (err, user) => {
      try {
        if (err) {
          return next(err)
        }

        if (!user) {
          return res.json(
            new ApiResponse(401, {}, "Incorrect email or password")
          )
        }

        const { accessToken, refreshToken } =
          await generateAccessTokenAndRefreshToken(user.id)

        const options = {
          httpOnly: true,
          secure: false,
        }

        return res
          .status(301)
          .cookie("accessToken", accessToken, options)
          .cookie("refreshToken", refreshToken, options)
          .redirect("http://localhost:3000/ioabhishek")
      } catch (error) {
        return next(error)
      }
    }
  )
}

export const emailPasswordRegister = async (req, res, next) => {
  const body = req.body

  const existedUser = await prisma.user.findUnique({
    where: {
      email: body.email,
    },
  })

  if (existedUser) {
    return next(ApiError(409, "User with email or username already exists"))
  }

  const salt = bcrypt.genSaltSync(10)
  body.password = bcrypt.hashSync(body.password, salt)

  const createdUser = await prisma.user.create({
    data: {
      name: body.name,
      email: body.email,
      username: body.username,
      password: body.password,
      isEmailVerified: false,
      loginType: "EMAIL_PASSWORD",
    },
  })

  if (!createdUser) {
    return next(
      ApiError(500, "Something went wrong while registering the user")
    )
  }

  return res
    .status(201)
    .json(
      new ApiResponse(
        200,
        { user: createdUser },
        "Users registered successfully."
      )
    )
}
