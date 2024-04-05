import passport from "passport"
import prisma from "../DB/db.config.js"
import ApiError from "../utils/ApiError.js"
import jwt from "jsonwebtoken"

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
