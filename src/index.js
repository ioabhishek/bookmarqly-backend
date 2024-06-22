import express from "express"
import passport from "./passport.js"
import AuthRoutes from "./routes/auth.route.js"
import CollectionRoutes from "./routes/collection.route.js"
import cors from "cors"
import cookieParser from "cookie-parser"
import bodyParser from "body-parser"
import "dotenv/config"

const port = process.env.PORT || 4000
const app = express()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(bodyParser.json())
app.use(passport.initialize())

app.use(
  cors({
    origin: "http://localhost:3000",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
)

app.use("/auth", AuthRoutes)
app.use("/collection", CollectionRoutes)

app.listen(port, () => {
  console.log(`Now listening on port ${port}`)
})
