const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const AccountSchema = new mongoose.Schema({
  email: String,
  pwd: String,
  phone: String,
  active: Boolean,
  image: String,
  role: String,
  verify_token: String,
});

AccountSchema.pre("save", async function (next) {
  if (!this.isModified("pwd")) return next();
  const salt = await bcrypt.genSalt(10);
  this.pwd = await bcrypt.hash(this.pwd, salt);
  next();
});

module.exports = mongoose.model("accounts", AccountSchema);
