const express = require("express");
const router = express.Router();
const db = require("../db");
const ExpressError = require("../expressError");
const User = require("../models/user");
const Message = require("../models/message");
const { ensureLoggedIn } = require("../middleware/auth");

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/
router.get("/:id", ensureLoggedIn, async (req, res, next) => {
  try {
    const message = await Message.get(req.params.id);
    if (
      req.user === message.from_user.username ||
      req.user === message.to_user.username
    ) {
      return res.json({ message });
    } else {
      throw new ExpressError("Unauthorized.", 401);
    }
  } catch (err) {
    return next(err);
  }
});

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/

router.post("/", ensureLoggedIn, async (req, res, next) => {
  try {
    const newMessage = await Message.create(req.body);
    return res.json({ newMessage });
  } catch (err) {
    return next(err);
  }
});
/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

router.post("/:id/read", ensureLoggedIn, async (req, res, next) => {
  try {
    const message = await Message.get(req.params.id);
    if (req.user === message.to_user.username) {
      const result = await Message.markRead(req.params.id);
      return res.json({"message":"Marked as read."})
    } else {
      throw new ExpressError("Unauthorized.", 401);
    }
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
