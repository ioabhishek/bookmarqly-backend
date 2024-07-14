import passport from "passport"
import prisma from "../DB/db.config.js"
import ApiError from "../utils/ApiError.js"
import jwt from "jsonwebtoken"
import bcrypt from "bcryptjs"
import crypto from "crypto"
import { ApiResponse } from "../utils/ApiResponse.js"
import { USER_TEMPORARY_TOKEN_EXPIRY, UserLoginType } from "../constants.js"
import { emailVerificationMailgenContent, sendEmail } from "../utils/mail.js"
import { ErrorResponse } from "../utils/ErrorResponse.js"

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
        expiresIn: "1w",
      }
    )

    // Generate access token
    const refreshToken = jwt.sign(
      {
        id: user.id,
      },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "1m" }
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
    secure: true,
  }

  return res
    .status(301)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .redirect(
      `http://localhost:3000/login?user=${user?.username}&accessToken=${accessToken}&refreshToken=${refreshToken}`
    )
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
  const token =
    req.cookies.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "")

  // const token = req.header("Authorization")?.replace("Bearer ", "")

  // If no token then return Error
  if (!token) {
    // throw ApiError(401, "Unauthorized request")
    return res.status(401).json(new ErrorResponse(401, "Unauthorized request"))
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
        name: true,
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
    // throw ApiError(401, error?.message || "Invalid access token")
    return res
      .status(401)
      .json(new ApiResponse(401, {}, error?.message || "Invalid access token"))
  }
}

export const verifyUser = async (req, res, next) => {
  const token =
    req.cookies.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "")

  if (token) {
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)

    // Using id from the decoded token find user in Database
    const user = await prisma.user.findUnique({
      where: {
        id: decodedToken.id,
      },
      select: {
        id: true,
        name: true,
        email: true,
        username: true,
        picture: true,
        isEmailVerified: true,
        loginType: true,
      },
    })

    if (user) {
      req.user = user
    }

    next()
  }
}

export const refreshAccessToken = async (req, res, next) => {
  const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

  if (!incomingRefreshToken) {
    return res.status(401).json(new ErrorResponse(401, "Unauthorized request"))
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
      secure: true,
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

export const registerUser = async (req, res, next) => {
  const { name, email, username, password } = req.body

  const existedUser = await prisma.user.findFirst({
    where: {
      OR: [{ email: email }, { username: username }],
    },
  })

  if (existedUser) {
    // return next(ApiError(409, "User with email or username already exists"))
    return res
      .status(409)
      .json(
        new ApiResponse(409, {}, "User with email or username already exists")
      )
  }

  const salt = bcrypt.genSaltSync(10)
  const hashedPass = bcrypt.hashSync(password, salt)

  /**
   * unHashedToken: unHashed token is something we will send to the user's mail
   * hashedToken: we will keep record of hashedToken to validate the unHashedToken in verify email controller
   * tokenExpiry: Expiry to be checked before validating the incoming token
   */
  const { unHashedToken, hashedToken, tokenExpiry } = generateTemporaryToken()

  // console.log(unHashedToken, hashedToken, tokenExpiry)

  const user = await prisma.user.create({
    data: {
      name: name,
      email: email,
      username: username,
      password: hashedPass,
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
      // `${req.protocol}://${req.get(
      //   "host"
      // )}/auth/users/verify-email/${unHashedToken}`
      `http://localhost:3000/verify-email/?token=${unHashedToken}`
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
  // const { verificationToken } = req.params
  const { verificationToken } = req.body

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

  // console.log(user?.emailVerificationExpiry > new Date().getTime())

  if (
    !user ||
    !(
      user.emailVerificationExpiry &&
      user.emailVerificationExpiry > new Date().getTime()
    )
  ) {
    return res
      .status(489)
      .json(new ApiResponse(489, {}, "Token is invalid or expired"))
  }

  await prisma.user.update({
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
  // .redirect(`http://localhost:3000/login`)
}

export const resendEmailVerification = async (req, res, next) => {
  const { email } = req.body

  const findUser = await prisma.user.findUnique({
    where: {
      // id: req.user?.id,
      email: email,
    },
  })

  if (!findUser) {
    // return next(ApiError(404, "User does not exists"))
    return res.status(404).json(new ErrorResponse(404, "User does not exists"))
  }

  if (findUser?.isEmailVerified) {
    // return next(ApiError(409, "Email is already verified!"))
    return res
      .status(409)
      .json(new ErrorResponse(409, "Email is already verified!"))
  }

  const { unHashedToken, hashedToken, tokenExpiry } = generateTemporaryToken()

  const user = await prisma.user.update({
    where: {
      id: findUser.id,
    },
    data: {
      emailVerificationToken: hashedToken,
      emailVerificationExpiry: tokenExpiry,
    },
  })

  await sendEmail({
    email: user?.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
      user?.username,
      // `${req.protocol}://${req.get(
      //   "host"
      // )}/auth/users/verify-email/${unHashedToken}`
      `http://localhost:3000/verify-email/?token=${unHashedToken}`
    ),
  })

  return res
    .status(201)
    .json(new ApiResponse(201, {}, "Mail has been sent to your mail ID"))
}

export const loginUser = async (req, res, next) => {
  const { email, password } = req.body

  if (!email || !password) {
    return next(ApiError(400, "Username or email is required"))
  }

  const findUser = await prisma.user.findUnique({
    where: {
      email: email,
    },
  })

  if (!findUser) {
    return res.status(404).json(new ErrorResponse(404, "User does not exist"))
  }

  if (findUser.loginType !== UserLoginType.EMAIL_PASSWORD) {
    return next(
      ApiError(
        400,
        "You have previously registered using " +
          findUser.loginType?.toLowerCase() +
          ". Please use the " +
          findUser.loginType?.toLowerCase() +
          " login option to access your account."
      )
    )
  }

  const isPasswordValid = bcrypt.compareSync(password, findUser.password)

  if (!isPasswordValid) {
    return res
      .status(403)
      .json(new ApiResponse(403, {}, "Invalid user credentials"))
  }

  const { accessToken, refreshToken } =
    await generateAccessTokenAndRefreshToken(findUser.id)

  const loggedInUser = await prisma.user.findUnique({
    where: {
      id: findUser.id,
    },
    select: {
      name: true,
      email: true,
      username: true,
      isEmailVerified: true,
      picture: true,
      loginType: "EMAIL_PASSWORD",
    },
  })

  const options = {
    httpOnly: true,
    // secure: process.env.NODE_ENV === "production",
    secure: true,
  }

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        { user: loggedInUser, accessToken, refreshToken },
        "User logged in successfully"
      )
    )
}

export const logoutUser = async (req, res, next) => {
  await prisma.user.update({
    where: {
      id: req.user?.id,
    },
    data: {
      refreshToken: null,
    },
  })

  // const options = {
  //   httpOnly: true,
  //   secure: process.env.NODE_ENV === "production",
  // }

  return res
    .status(200)
    .clearCookie("accessToken")
    .clearCookie("refreshToken")
    .json(new ApiResponse(200, {}, "User logged out"))
}

export const forgotPasswordRequest = async (req, res, next) => {
  const { email } = req.body

  const findUser = await prisma.user.findUnique({
    where: {
      email: email,
    },
  })

  if (!findUser) {
    // return next(ApiError(404, "User does not exist"))
    return res.status(404).json(new ErrorResponse(404, "User does not exists"))
  }

  if (findUser && findUser.loginType === "Google") {
    return res
      .status(409)
      .json(new ErrorResponse(409, "Email already used with Google"))
  }

  const { unHashedToken, hashedToken, tokenExpiry } = generateTemporaryToken()

  const user = await prisma.user.update({
    where: {
      id: findUser.id,
    },
    data: {
      forgotPasswordToken: hashedToken,
      forgotPasswordExpiry: tokenExpiry,
    },
  })

  await sendEmail({
    email: user?.email,
    subject: "Password reset request",
    mailgenContent: emailVerificationMailgenContent(
      user?.username,
      // `${req.protocol}://${req.get(
      //   "host"
      // )}/auth/users/reset-password/${unHashedToken}`
      `http://localhost:3000/reset-password/?token=${unHashedToken}`
    ),
  })

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        {},
        "Password reset mail has been sent on your mail id"
      )
    )
}

export const resetForgottenPassword = async (req, res, next) => {
  // const { resetToken } = req.params
  const { resetToken, newPassword } = req.body

  let hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex")

  const user = await prisma.user.findFirst({
    where: {
      forgotPasswordToken: hashedToken,
      // forgotPasswordExpiry: {
      //   gt: new Date().getTime().toString(),
      // },
    },
  })

  if (
    !user ||
    !(
      user.forgotPasswordExpiry &&
      user.forgotPasswordExpiry > new Date().getTime()
    )
  ) {
    return res
      .status(489)
      .json(new ErrorResponse(489, "Token is invalid or expired"))
  }

  // if (!user) {
  //   return next(ApiError(489, "Token is invalid or expired"))
  // }

  const salt = bcrypt.genSaltSync(10)
  const hashedPass = bcrypt.hashSync(newPassword, salt)

  await prisma.user.update({
    where: {
      id: user.id,
    },
    data: {
      forgotPasswordToken: null,
      forgotPasswordExpiry: null,
      password: hashedPass,
    },
  })

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password reset successfully"))
}

export const changeCurrentPassword = async (req, res, next) => {
  const { oldPassword, newPassword } = req.body

  const findUser = await prisma.user.findUnique({
    where: {
      id: req.user?.id,
    },
  })

  const isPasswordValid = bcrypt.compareSync(oldPassword, findUser.password)

  if (!isPasswordValid) {
    return next(ApiError(401, "Invalid old password"))
  }

  const salt = bcrypt.genSaltSync(10)
  const hashedPass = bcrypt.hashSync(newPassword, salt)

  await prisma.user.update({
    where: {
      id: findUser.id,
    },
    data: {
      password: hashedPass,
    },
  })

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"))
}

export const userDetails = async (req, res) => {
  const { isCollection } = req.body

  // Base select fields
  const selectFields = {
    name: true,
    email: true,
    username: true,
    isEmailVerified: true,
    picture: true,
    loginType: true,
  }

  if (isCollection) {
    selectFields.collection = {}
  }

  const findUser = await prisma.user.findUnique({
    where: {
      id: req?.user?.id,
    },
    select: selectFields,
  })

  if (!findUser) {
    return res.status(404).json(new ErrorResponse(404, "User does not exist"))
  }

  return res
    .status(200)
    .json(new ApiResponse(200, findUser, "Current user fetched successfully"))
}

export const getUser = async (req, res, next) => {
  const { username } = req.params
  const userId = req.user.id
  const usernameCompare = req.user.username

  // Base select fields
  const selectFields = {
    name: true,
    email: true,
    username: true,
    isEmailVerified: true,
    picture: true,
    loginType: true,
  }

  // Conditionally add the collection field
  if (userId && username === usernameCompare) {
    // User is the owner, include all collection fields
    selectFields.collection = {}
  } else {
    // User is not the owner, include only public collections
    selectFields.collection = {
      where: {
        isPublic: true,
      },
      // select: {
      //   // Include fields relevant to non-owners
      //   id: true,
      //   isPublic: true,
      // },
    }
  }

  try {
    const findUser = await prisma.user.findUnique({
      where: {
        username: username,
      },
      select: selectFields,
    })

    if (!findUser) {
      return res.status(404).json(new ErrorResponse(404, "User does not exist"))
    }

    return res
      .status(200)
      .json(new ApiResponse(200, findUser, "User details fetched successfuly"))
  } catch (error) {
    next(error)
  }
}
