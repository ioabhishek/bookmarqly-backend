import jwt from "jsonwebtoken"
import passport from "passport"
import prisma from "./DB/db.config.js"
import { Strategy as LocalStrategy } from "passport-local"
import { Strategy as GoogleStrategy } from "passport-google-oauth20"
import bcrypt from "bcryptjs"
import ApiError from "./utils/ApiError.js"
import { UserLoginType } from "./constants.js"

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (authAccessToken, authRefreshToken, profile, next) => {
      // Check if the user with email already exist
      let user = await prisma.user.findUnique({
        where: {
          email: profile?._json?.email,
        },
      })

      // If user already exists then return user
      if (user) {
        next(null, user)
      } else {
        // If user doesn't exist then create new user & save it in the database
        let createdUser = await prisma.user.create({
          data: {
            name: profile._json?.name,
            username: profile._json.email?.split("@")[0],
            email: profile._json.email,
            isEmailVerified: true,
            picture: profile._json?.picture,
            loginType: UserLoginType.GOOGLE,
          },
        })

        if (createdUser) {
          next(null, createdUser)
        } else {
          next(ApiError(500, "Error while registering the user"), null)
        }
      }
    }
  )
)

passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    async (email, password, next, done) => {
      try {
        // Check if the user with email already exist
        const user = await prisma.user.findUnique({
          where: {
            email: email,
          },
        })

        // If user already exists then return user
        if (user) {
          if (user.loginType == "EMAIL_PASSWORD") {
            if (!bcrypt.compareSync(password, user.password)) {
              // Check if password is correct or not
              return next(null, false, { message: "Invalid credentials" })
            } else {
              return next(null, user)
            }
          } else {
            return next(ApiError(401, "Invalid login method"))
          }
        } else {
          return next(null, false, { message: "No user found with this email" })
        }
      } catch (error) {
        return next(ApiError(500, "Error while login, please try again"), null)
      }
    }
  )
)

export default passport
