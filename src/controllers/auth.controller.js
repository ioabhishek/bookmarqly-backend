import passport from "passport"
import prisma from "../DB/db.config.js"
import ApiError from "../utils/ApiError.js"
import jwt from "jsonwebtoken"
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
