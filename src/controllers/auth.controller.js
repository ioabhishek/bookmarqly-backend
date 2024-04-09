import passport from "passport"
import prisma from "../DB/db.config.js"
import ApiError from "../utils/ApiError.js"
import jwt from "jsonwebtoken"
import bcrypt from "bcryptjs"
import crypto from "crypto"
import { ApiResponse } from "../utils/ApiResponse.js"
import { USER_TEMPORARY_TOKEN_EXPIRY } from "../constants.js"
import { emailVerificationMailgenContent, sendEmail } from "../utils/mail.js"

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

const generateTemporaryToken = () => {
  // This token should be client facing
  // for example: for email verification unHashedToken should go into the user's mail
  const unHashedToken = crypto.randomBytes(20).toString("hex")

  // This should stay in the DB to compare at the time of verification
  const hashedToken = crypto
    .createHash("sha256")
    .update(unHashedToken)
    .digest("hex")
  // This is the expiry time for the token (20 minutes)
  const tokenExpiry = `${Date.now() + USER_TEMPORARY_TOKEN_EXPIRY}`

  return { unHashedToken, hashedToken, tokenExpiry }
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
  passport.authenticate("local", { session: false }, async (err, user) => {
    try {
      if (err) {
        return next(err)
      }

      if (!user) {
        return res.json(new ApiResponse(401, {}, "Incorrect email or password"))
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
        .json(
          new ApiResponse(
            200,
            {
              ...user,
              password: undefined,
              refreshToken: undefined,
            },
            "Login success"
          )
        )
    } catch (error) {
      return next(error)
    }
  })(req, res, next)
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

export const resetForgottenPassword = async (req, res, next) => {
  const { oldPassword, newPassword } = req.body

  const user = await prisma.user.findUnique({
    where: {
      id: req.user?.id,
    },
  })

  if (!user) {
    return next(ApiError(401, "Please create an account to change password"))
  }

  const isPasswordValid = bcrypt.compareSync(oldPassword, user.password)

  if (!isPasswordValid) {
    return next(ApiError(400, "Invalid old password"))
  }

  const salt = bcrypt.genSaltSync(10)
  const newHashedPassword = bcrypt.hashSync(newPassword, salt)

  await prisma.user.update({
    where: {
      id: user.id,
    },
    data: {
      password: newHashedPassword,
    },
  })

  // check token expiration before updating the password
  // recieved request for password reset
  // check in db weather user exists and if yes then check login type. If not Email_Password then throw an error
  // If user and right login method encryt and update password in the db, and return succes message.
}

export const registerUser = async (req, res, next) => {
  const { name, email, username, password } = req.body

  const existedUser = await prisma.user.findFirst({
    where: {
      OR: [{ email: email }, { username: username }],
    },
  })

  if (existedUser) {
    return next(ApiError(409, "User with email or username already exists"))
  }

  const salt = bcrypt.genSaltSync(10)
  req.body.password = bcrypt.hashSync(password, salt)

  /**
   * unHashedToken: unHashed token is something we will send to the user's mail
   * hashedToken: we will keep record of hashedToken to validate the unHashedToken in verify email controller
   * tokenExpiry: Expiry to be checked before validating the incoming token
   */
  const { unHashedToken, hashedToken, tokenExpiry } = generateTemporaryToken()

  console.log(unHashedToken, hashedToken, tokenExpiry)

  const user = await prisma.user.create({
    data: {
      name: name,
      email: email,
      username: username,
      password: password,
      isEmailVerified: false,
      loginType: "EMAIL_PASSWORD",
      emailVerificationToken: hashedToken,
      emailVerificationExpiry: tokenExpiry,
    },
  })

  await sendEmail({
    email: user?.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
      user?.username,
      `${req.protocol}://${req.get(
        "host"
      )}/auth/users/verify-email/${unHashedToken}`
    ),
  })

  const createdUser = await prisma.user.findUnique({
    where: {
      id: user.id,
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
        "Users registered successfully and verification email has been sent on your email."
      )
    )
}

export const verifyEmail = async (req, res, next) => {
  const { verificationToken } = req.params
  // console.log("token is", verificationToken)

  if (!verificationToken) {
    return next(ApiError(400, "Email verification token is missing"))
  }

  // generate a hash from the token that we are receiving
  let hashedToken = crypto
    .createHash("sha256")
    .update(verificationToken)
    .digest("hex")

  // console.log("hashed token is", hashedToken)

  // While registering the user, same time when we are sending the verification mail
  // we have saved a hashed value of the original email verification token in the db
  // We will try to find user with the hashed token generated by received token
  // If we find the user another check is if token expiry of that token is greater than current time if not that means it is expired

  const user = await prisma.user.findFirst({
    where: {
      emailVerificationToken: hashedToken,
      // emailVerificationExpiry: {
      //   gt: new Date().toISOString(),
      // },
    },
  })

  console.log(user?.emailVerificationExpiry > new Date())

  if (!user) {
    return next(ApiError(489, "Token is invalid or expired"))
  }

  const updateUser = await prisma.user.update({
    where: {
      id: user.id,
    },
    data: {
      emailVerificationToken: null,
      emailVerificationExpiry: null,
      isEmailVerified: true,
    },
  })

  return res
    .status(200)
    .json(new ApiResponse(200, { isEmailVerified: true }, "Email is verified"))
}
