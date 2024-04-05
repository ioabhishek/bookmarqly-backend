import passport from "passport"

export const googleLogin = (req, res, next) => {
  passport.authenticate("google", { scope: ["profile", "email"] })(
    req,
    res,
    next
  )
}

export const googleLoginCallback = (req, res) => {
  passport.authenticate("google", {
    failureRedirect: "/login/failed",
    session: false,
  })(req, res, () => {
    res.cookie("accessToken", req.user.accessToken, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
      secure: false,
    })
    res.redirect("http://localhost:3000/ioabhishek")
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
