
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { users, nextId } from "../data.js";

export const verifyCallback = (accessToken, refreshToken, profile, done) => {
  try {
    const googleId = profile.id;
    const email = profile.emails[0].value;
    const name = profile.displayName;

    // 1. Find returning users by Google ID first.
    const existingGoogleUser = users.find(
      (user) => user.googleId === googleId
    );

    if (existingGoogleUser) {
      return done(null, existingGoogleUser);
    }

    // 2. Find an existing local account by email.
    const existingEmailUser = users.find(
      (user) => user.email === email
    );

    if (existingEmailUser) {
      // Only link an account when Google's email is verified.
      if (profile._json.email_verified === true) {
        existingEmailUser.googleId = googleId;
        return done(null, existingEmailUser);
      }

      return done(null, false);
    }

    // 3. Create a new user when no match exists.
    const newUser = {
      id: nextId(),
      googleId,
      email,
      name,
      role: "member",
    };

    users.push(newUser);
    return done(null, newUser);
  } catch (err) {
    return done(err);
  }
};

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    verifyCallback
  )
);
