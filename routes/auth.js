const express = require("express");
const router = express.Router();
const db = require("../db");
const ExpressError = require("../expressError");
const User = require("../models/user");
const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (await User.authenticate(username, password)) {
      User.updateLoginTimestamp(username);
      const token = jwt.sign({ username }, SECRET_KEY);
      return res.json({ token });
    } else {
      throw new ExpressError("Invalid username/password", 400);
    }
  } catch (err) {
    return next(err);
  }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 */

router.post("/register", async (req, res, next) => {
  try {
    const results = await User.register(req.body);
    const { username } = results;
    // login user and update last login
    User.updateLoginTimestamp(username);
    const token = jwt.sign({ username }, SECRET_KEY);
    return res.json({ message: "Logged in!", token });
  } catch (err) {
    if (err.code === "23505") {
      return next(
        new ExpressError("Username already taken. Please try again.", 400)
      );
    }
    return next(err);
  }
});

module.exports = router;
