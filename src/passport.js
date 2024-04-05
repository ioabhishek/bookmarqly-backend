import jwt from "jsonwebtoken"
import passport from "passport"
import prisma from "./DB/db.config.js"
import { PrismaClient } from "@prisma/client"
import { Strategy as LocalStrategy } from "passport-local"
import { Strategy as GoogleStrategy } from "passport-google-oauth20"
import bcrypt from "bcryptjs"

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (authAccessToken, authRefreshToken, profile, done) => {
      try {
        let user = await prisma.user.findUnique({
          where: {
            email: profile?._json?.email,
          },
        })

        if (!user) {
          const userData = {
            name: profile._json?.name || "",
            username: profile._json?.sub || "",
            email: profile._json?.email || "",
            picture: profile._json?.picture || "",
            refreshToken: "",
          }

          user = await prisma.user.create({
            data: userData,
          })
        }

        done(null, { user })
      } catch (error) {
        done(error)
      }
    }
  )
)

export default passport
