/** User class for message.ly */
const bcrypt = require("bcrypt");
const { BCRYPT_WORK_FACTOR } = require("../config");
const db = require("../db");
const ExpressError = require("../expressError");

/** User of the site. */

class User {
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    if (!username || !password || !first_name || !last_name || !phone) {
      throw new ExpressError("All fields are required.", 400);
    }
    const hashedPW = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const results = await db.query(
      `INSERT INTO users (username,password,first_name,last_name,phone, join_at) VALUES ($1,$2,$3,$4,$5, current_timestamp) RETURNING username,password,first_name,last_name,phone, join_at`,
      [username, hashedPW, first_name, last_name, phone]
    );
    return results;
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    if (!username || !password) {
      throw new ExpressError("Username and password required.", 400);
    }
    const results = await db.query(
      `
    SELECT username, password
    FROM users
    WHERE username = $1
    `,
      [username]
    );
    const user = results.rows[0];
    if (user) {
      return await bcrypt.compare(password, user.password);
    } else {
      throw new ExpressError("Invalid username/password.", 400);
    }
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    if (!username) {
      throw new ExpressError("Please provide a valid username", 400);
    }
    const results = await db.query(
      `
      UPDATE users SET last_login_at=(current_timestamp) WHERE username=$1
    `,
      [username]
    );
    return results;
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {}

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {}

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {}

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {id, first_name, last_name, phone}
   */

  static async messagesTo(username) {}
}

module.exports = User;
