var express = require("express");
var router = express.Router();
const AccountModel = require("../models/account.model");
const multer = require("multer");
const path = require("path");

const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { body, validationResult } = require("express-validator");

// thiết lập thư mục lưu trữ
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "./public/images");
  },
  filename: (req, file, cb) => {
    cb(null, `img-${Date.now()}${path.extname(file.originalname)}`);
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
});

// middleware check JWT Token
const authenticateToken = (req, res, next) => {
  const authHeader = req.header("Authorization");
  if (!authHeader) return res.status(401).send("Access Denied");

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).send("Access Denied");

  //console.log("token: " + token);
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    //console.log(decoded.id);
    req.account = decoded;
    next();
  } catch (err) {
    //console.log(err);
    res.status(400).send("Invalid Token");
  }
};

/* GET users listing. */
router.get("/", async (req, res) => {
  var accounts = await AccountModel.find();
  res.render("account/index", { accounts });
});

router.get("/create", (req, res) => {
  res.render("account/create");
});

router.post(
  "/create",

  [
    upload.single("image"),
    body("email")
      .notEmpty()
      .withMessage("Please input email.")
      .isEmail()
      .withMessage("Email not valid."),
    body("pwd")
      //.notEmpty().withMessage("Please input password.")
      .isLength({ min: 3 })
      .withMessage("Password must be at least 3 characters."),
    body("confirm")
      .custom((value, { req }) => value === req.body.pwd)
      .withMessage("Password and confirm must be the same."),
    body("phone")
      .isLength({ min: 10 })
      .withMessage("Phone must be at least 10 characters."),
    // body("image").notEmpty().withMessage("Please choose image to upload."),
  ],

  async (req, res) => {
    const errors = validationResult(req);
    //console.log(errors.errors);
    if (!errors.isEmpty()) {
      return res.render("account/create", { errors: errors.errors });
    }
    try {
      const { email, pwd, phone, role } = req.body;

      const image = req.file ? req.file.filename : "";

      const account = new AccountModel({
        email,
        pwd,
        phone,
        role,
        image,
        active: false,
      });

      await account.save();
      res.redirect("/acc");
    } catch (error) {
      console.error(error);
      res.render("account/create");
    }
  }
);

router.get("/register", (req, res) => {
  return res.render("account/register");
});

router.post("/register", async (req, res) => {
  const { email, pwd } = req.body;
  try {
    let account = await AccountModel.findOne({ email });
    if (account) {
      return res.status(400).send({ message: "Email is used." });
    }

    const verifyToken = jwt.sign({ email }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    account = new AccountModel({
      email,
      pwd,
      role: "user",
      active: false,
      verify_token: verifyToken,
    });

    await account.save();

    // send activation email
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const link = `${req.protocol}://${req.get(
      "host"
    )}/acc/verify/${verifyToken}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Activation Account",
      html: `<h2>Activation Account</h2><p>Please click this link to activate your account:</p><a href="${link}">Activate</a>`,
    });

    res
      .status(200)
      .send(
        "Register successfully. Please check your email to activate account!"
      );
  } catch (err) {
    console.log(err);
    res.status(500).send({ message: "Internal Server Error" });
  }
});

router.get("/verify/:token", async (req, res) => {
  const token = req.params;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const account = await AccountModel.findOne({ email: decoded.email });
    if (!account) {
      return res.status(400).send("Token not valid.");
    }
    if (account.active) {
      return res.status(400).send("Account already activated.");
    }
    account.active = true;
    account.verify_token = null;
    await account.save();

    res.status(200).send("Account activated successfully.");
  } catch (err) {
    console.log(err);
    res.status(500).send({ message: "Internal Server Error" });
  }
});

router.get("/login", (req, res) => {
  return res.render("account/login");
});

router.post("/login", async (req, res) => {
  const { email, pwd } = req.body;

  try {
    const account = await AccountModel.findOne({ email });
    if (!account) {
      return res.status(400).send("Email or Password is incorrect.");
    }

    // check account is activate
    if (!account.active) {
      return res
        .status(400)
        .send("Account not activated. Please check your email!");
    }

    const isMatch = await bcrypt.compare(pwd, account.pwd);
    if (!isMatch) {
      return res.status(400).send("Email or Password is incorrect.");
    }

    // password right
    const token = jwt.sign({ id: account._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    res.status(200).json({
      message: "Login successfully.",
      token,
    });
  } catch (err) {
    console.log(err);
    res.status(500).send({ message: "Internal Server Error" });
  }
});

router.get("/getAcc", authenticateToken, async (req, res) => {
  try {
    const id = req.account.id;

    const accounts = await AccountModel.find().select("-pwd");
    //console.log(accounts);
    if (!accounts) {
      return res.status(400).send("Account not found.");
    }
    res.status(200).json({
      message: "Account retrieved successfully.",
      accounts,
    });
  } catch (err) {
    console.log(err);
    res.status(500).send({ message: "Internal Server Error" });
  }
});

module.exports = router;
