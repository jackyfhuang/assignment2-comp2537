require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const path = require("path");

const app = express();
const port = process.env.PORT || 3000;

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String
});
const User = mongoose.model("User", userSchema);

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/");
  }
  next();
}

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    dbName: process.env.SESSION_DB_NAME
  }),
  cookie: { maxAge: 1000 * 60 * 60 }
}));

app.get("/", (req, res) => {
  res.render("index", { user: req.session.user });
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  const schema = Joi.object({
    name: Joi.string().min(1).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required()
  });

  const validationResult = schema.validate({ name, email, password });

  if (validationResult.error) {
    return res.send(`<p>${validationResult.error.details[0].message}</p><a href="/signup">Try again</a>`);
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const existingUser = await User.findOne({ email: email });
    if (existingUser) {
      return res.send(`<p>Email already in use.</p><a href="/signup">Try again</a>`);
    }

    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    req.session.user = { name: newUser.name, email: newUser.email };
    res.redirect("/members");
  } catch (err) {
    console.error(err);
    res.send("Error signing up.");
  }
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const validationResult = schema.validate({ email, password });

  if (validationResult.error) {
    return res.send(`<p>${validationResult.error.details[0].message}</p><a href="/login">Try again</a>`);
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.send(`<p>User not found.</p><a href="/login">Try again</a>`);
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.send(`<p>Invalid password.</p><a href="/login">Try again</a>`);
    }

    req.session.user = { name: user.name, email: user.email };
    res.redirect("/");
  } catch (err) {
    console.error(err);
    res.send("Error logging in.");
  }
});

app.get("/members", requireLogin, (req, res) => {
  const images = ["cat.jpg", "dog.jpg", "frog.jpg"];
  const randomImage = images[Math.floor(Math.random() * images.length)];
  res.render("members", { user: req.session.user, image: randomImage });
});

app.get("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.send("Error logging out.");
    }
    res.redirect("/");
  });
});

app.use((req, res) => {
  res.status(404).render("404");
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
