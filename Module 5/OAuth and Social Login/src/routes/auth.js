
import { Router } from "express";
import passport from "passport";
import { signToken } from "../utils/jwt.js";

const router = Router();

router.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

router.get(
  "/google/callback",
  passport.authenticate("google", {
    session: false,
    failureRedirect: "/login",
  }),
  (req, res) => {
    const token = signToken({
      sub: req.user.id,
      role: req.user.role,
    });

    return res.json({ token });
  }
);

export default router;
