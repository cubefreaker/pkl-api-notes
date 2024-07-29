const express = require("express");
const moment = require("moment-timezone");

require("dotenv").config();

const knex = require("knex")({
  client: "mysql",
  connection: {
    host: "127.0.0.1",
    port: process.env.MYSQL_PORT,
    user: process.env.MYSQL_U,
    password: process.env.MYSQL_P,
    database: process.env.MYSQL_DB,
  },
});

const jwt = require("jsonwebtoken");

const app = express();

function responseHandler(res, httpCode, success, message, data) {
  res.status(httpCode).json({
    success,
    message,
    data,
  });
}

function checkAuthorization(req, res, next) {
  try {
    const token = req.headers?.authorization?.split(" ")[1] || null;
    if (!token) {
      return responseHandler(
        res,
        200,
        false,
        "Error!Token was not provided.",
        null
      );
    }
    const decodedToken = jwt.verify(token, process.env.SECRET_KEY);
    req.decodedToken = decodedToken;
    next();
  } catch (err) {
    return responseHandler(res, 401, false, "Invalid token", null);
  }
}

function getTimestamp() {
  return moment().tz("Asia/Jakarta").format("YYYY-MM-DD HH:mm:ss");
}

app.use(express.json());

app.post("/login", async (req, res, next) => {
  let { email, password } = req.body;
  let token;
  let existingUser;

  try {
    existingUser = await knex("users").where("email", email).first();
  } catch (err) {
    return responseHandler(res, 500, false, err, null);
  }

  if (!existingUser || existingUser.password != password) {
    return responseHandler(res, 401, false, "Invalid credentials", null);
  }

  try {
    //Creating jwt token
    token = jwt.sign(
      {
        userId: existingUser.id,
        email: existingUser.email,
      },
      process.env.SECRET_KEY,
      { expiresIn: "1h" }
    );
    responseHandler(res, 200, true, "Login successful", {
      userId: existingUser.id,
      email: existingUser.email,
      token: token,
    });
  } catch (err) {
    return responseHandler(res, 500, false, err, null);
  }
});

app.post("/signup", async (req, res, next) => {
  const { firstname, lastname, email, password } = req.body;
  let checkUser = await knex("users").where("email", email).first();
  if (checkUser) {
    return responseHandler(res, 409, false, "User already exists", null);
  }

  let newUser;
  try {
    let newUserId = await knex("users").insert({
      firstname,
      lastname,
      email,
      username: email,
      password,
      created_at: getTimestamp(),
    });
    newUser = await knex("users").where("id", newUserId[0]).first();
  } catch (err) {
    return responseHandler(res, 500, false, err, null);
  }

  let token;
  try {
    token = jwt.sign(
      {
        userId: newUser.id,
        email: newUser.email,
      },
      process.env.SECRET_KEY,
      { expiresIn: "1h" }
    );

    await knex("users").where("id", newUser.id).update({
      token,
    });

    return responseHandler(res, 200, true, "User created successfully", {
      userId: newUser.id,
      email: newUser.email,
      token: token,
    });
  } catch (err) {
    return responseHandler(res, 500, false, err, null);
  }
});

app.get("/notes", checkAuthorization, async (req, res) => {
  try {
    let userNotes = await knex("notes").where(
      "user_id",
      req.decodedToken.userId
    );
    return responseHandler(
      res,
      200,
      true,
      "Notes fetched successfully",
      userNotes
    );
  } catch (err) {
    return responseHandler(res, 500, false, err, null);
  }
});

app.post("/notes", checkAuthorization, async (req, res, next) => {
  let newNote;
  try {
    const { title, content } = req.body;
    let newNoteId = await knex("notes").insert({
      title,
      content,
      user_id: req.decodedToken.userId,
      created_at: getTimestamp(),
    });

    newNote = await knex("notes").where("id", newNoteId[0]).first();
    return responseHandler(
      res,
      200,
      true,
      "Note created successfully",
      newNote
    );
  } catch (err) {
    return responseHandler(res, 500, false, err, null);
  }
});

app.patch("/notes/:noteId", checkAuthorization, async (req, res, next) => {
  let updatedNote;
  try {
    const { title, content } = req.body;
    const noteId = req.params.noteId;
    await knex("notes").where("id", noteId).update({
      title,
      content,
      updated_at: getTimestamp(),
    });

    updatedNote = await knex("notes").where("id", noteId).first();
    return responseHandler(
      res,
      200,
      true,
      "Note updated successfully",
      updatedNote
    );
  } catch (err) {
    return responseHandler(res, 500, false, err, null);
  }
});

app.delete("/notes/:noteId", checkAuthorization, async (req, res, next) => {
  let deletedNote;
  try {
    const noteId = req.params.noteId;
    deletedNote = await knex("notes").where("id", noteId).first();
    await knex("notes").where("id", noteId).del();
    return responseHandler(
      res,
      200,
      true,
      "Note deleted successfully",
      deletedNote
    );
  } catch (err) {
    return responseHandler(res, 500, false, err, null);
  }
});

app.get("/", (req, res) => {
  return res.send("Hello World!");
});

app.use((error, req, res, next) => {
  if (res.headerSent) {
    return next(error);
  }
  return responseHandler(
    res,
    error.httpCode || 500,
    false,
    error.message || "An unknown error occurred",
    null
  );
});

app.listen(5000, () => {
  console.log("Server is running on port 5000");
});
