// Started at 11:03 6-26-2022

const cloudinary = require("cloudinary").v2;

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET,
  secure: true,
});

module.exports = cloudinary;

const jwt = require("jsonwebtoken");
const User = require("../models/user");
const EmailVerificationToken = require("../models/emailVerificationToken");
const PasswordResetToken = require("../models/passwordResetToken");
const { isValidObjectId } = require("mongoose");
const { generateOTP, generateMailTransporter } = require("../utils/mail");
const { sendError, generateRandomByte } = require("../utils/helper");

exports.create = async (req, res) => {
  const { name, email, password } = req.body;

  const oldUser = await User.findOne({ email });

  if (oldUser) return sendError(res, "This email is already in use!");

  const newUser = new User({ name, email, password });
  await newUser.save();

  // generate 6 digit otp
  let OTP = generateOTP();

  // store otp inside our db
  const newEmailVerificationToken = new EmailVerificationToken({
    owner: newUser._id,
    token: OTP,
  });

  await newEmailVerificationToken.save();

  // send that otp to our user

  var transport = generateMailTransporter();

  transport.sendMail({
    from: "verification@reviewapp.com",
    to: newUser.email,
    subject: "Email Verification",
    html: `
      <p>Your verification OTP</p>
      <h1>${OTP}</h1>

    `,
  });

  res.status(201).json({
    message:
      "Please verify your email. OTP has been sent to your email accont!",
  });
};

exports.verifyEmail = async (req, res) => {
  const { userId, OTP } = req.body;

  if (!isValidObjectId(userId)) return res.json({ error: "Invalid user!" });

  const user = await User.findById(userId);
  if (!user) return sendError(res, "user not found!", 404);

  if (user.isVerified) return sendError(res, "user is already verified!");

  const token = await EmailVerificationToken.findOne({ owner: userId });
  if (!token) return sendError(res, "token not found!");

  const isMatched = await token.compareToken(OTP);
  if (!isMatched) return sendError(res, "Please submit a valid OTP!");

  user.isVerified = true;
  await user.save();

  await EmailVerificationToken.findByIdAndDelete(token._id);

  var transport = generateMailTransporter();

  transport.sendMail({
    from: "verification@reviewapp.com",
    to: user.email,
    subject: "Welcome Email",
    html: "<h1>Welcome to our app and thanks for choosing us.</h1>",
  });
  res.json({ message: "Your email is verified." });
};

exports.resendEmailVerificationToken = async (req, res) => {
  const { userId } = req.body;

  const user = await User.findById(userId);
  if (!user) return sendError(res, "user not found!");

  if (user.isVerified)
    return sendError(res, "This email id is already verified!");

  const alreadyHasToken = await EmailVerificationToken.findOne({
    owner: userId,
  });
  if (alreadyHasToken)
    return sendError(
      res,
      "Only after one hour you can request for another token!"
    );

  // generate 6 digit otp
  let OTP = generateOTP();

  // store otp inside our db
  const newEmailVerificationToken = new EmailVerificationToken({
    owner: user._id,
    token: OTP,
  });

  await newEmailVerificationToken.save();

  // send that otp to our user

  var transport = generateMailTransporter();

  transport.sendMail({
    from: "verification@reviewapp.com",
    to: user.email,
    subject: "Email Verification",
    html: `
      <p>Your verification OTP</p>
      <h1>${OTP}</h1>

    `,
  });

  res.json({
    message: "New OTP has been sent to your registered email accout.",
  });
};

exports.forgetPassword = async (req, res) => {
  const { email } = req.body;

  if (!email) return sendError(res, "email is missing!");

  const user = await User.findOne({ email });
  if (!user) return sendError(res, "User not found!", 404);

  const alreadyHasToken = await PasswordResetToken.findOne({ owner: user._id });
  if (alreadyHasToken)
    return sendError(
      res,
      "Only after one hour you can request for another token!"
    );

  const token = await generateRandomByte();
  const newPasswordResetToken = await PasswordResetToken({
    owner: user._id,
    token,
  });
  await newPasswordResetToken.save();

  const resetPasswordUrl = `http://localhost:3000/reset-password?token=${token}&id=${user._id}`;

  const transport = generateMailTransporter();

  transport.sendMail({
    from: "security@reviewapp.com",
    to: user.email,
    subject: "Reset Password Link",
    html: `
      <p>Click here to reset password</p>
      <a href='${resetPasswordUrl}'>Change Password</a>

    `,
  });

  res.json({ message: "Link sent to your email!" });
};

exports.sendResetPasswordTokenStatus = (req, res) => {
  res.json({ valid: true });
};

exports.resetPassword = async (req, res) => {
  const { newPassword, userId } = req.body;

  const user = await User.findById(userId);
  const matched = await user.comparePassword(newPassword);
  if (matched)
    return sendError(
      res,
      "The new password must be different from the old one!"
    );

  user.password = newPassword;
  await user.save();

  await PasswordResetToken.findByIdAndDelete(req.resetToken._id);

  const transport = generateMailTransporter();

  transport.sendMail({
    from: "security@reviewapp.com",
    to: user.email,
    subject: "Password Reset Successfully",
    html: `
      <h1>Password Reset Successfully</h1>
      <p>Now you can use new password.</p>

    `,
  });

  res.json({
    message: "Password reset successfully, now you can use new password.",
  });
};

exports.signIn = async (req, res, next) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return sendError(res, "Email/Password mismatch!");

  const matched = await user.comparePassword(password);
  if (!matched) return sendError(res, "Email/Password mismatch!");

  const { _id, name, role } = user;

  const jwtToken = jwt.sign({ userId: _id }, process.env.JWT_SECRET);

  res.json({ user: { id: _id, name, email, role, token: jwtToken } });
};

const { sendError } = require("../utils/helper");
const cloudinary = require("../cloud");
const Movie = require("../models/movie");
const { isValidObjectId } = require("mongoose");

exports.uploadTrailer = async (req, res) => {
  const { file } = req;
  if (!file) return sendError(res, "Video file is missing!");

  const { secure_url: url, public_id } = await cloudinary.uploader.upload(
    file.path,
    {
      resource_type: "video",
    }
  );
  res.status(201).json({ url, public_id });
};

exports.createMovie = async (req, res) => {
  const { file, body } = req;

  const {
    title,
    storyLine,
    director,
    releseDate,
    status,
    type,
    genres,
    tags,
    cast,
    writers,
    trailer,
    language,
  } = body;

  const newMovie = new Movie({
    title,
    storyLine,
    releseDate,
    status,
    type,
    genres,
    tags,
    cast,
    trailer,
    language,
  });

  if (director) {
    if (!isValidObjectId(director))
      return sendError(res, "Invalid director id!");
    newMovie.director = director;
  }

  if (writers) {
    for (let writerId of writers) {
      if (!isValidObjectId(writerId))
        return sendError(res, "Invalid writer id!");
    }

    newMovie.writers = writers;
  }

  // uploading poster
  const {
    secure_url: url,
    public_id,
    responsive_breakpoints,
  } = await cloudinary.uploader.upload(file.path, {
    transformation: {
      width: 1280,
      height: 720,
    },
    responsive_breakpoints: {
      create_derived: true,
      max_width: 640,
      max_images: 3,
    },
  });

  const finalPoster = { url, public_id, responsive: [] };

  const { breakpoints } = responsive_breakpoints[0];
  if (breakpoints.length) {
    for (let imgObj of breakpoints) {
      const { secure_url } = imgObj;
      finalPoster.responsive.push(secure_url);
    }
  }

  newMovie.poster = finalPoster;

  await newMovie.save();

  res.status(201).json({
    id: newMovie._id,
    title,
  });
};

exports.updateMovieWithoutPoster = async (req, res) => {
  const { movieId } = req.params;

  if (!isValidObjectId(movieId)) return sendError(res, "Invalid Movie ID!");

  const movie = await Movie.findById(movieId);
  if (!movie) return sendError(res, "Movie Not Found!", 404);

  const {
    title,
    storyLine,
    director,
    releseDate,
    status,
    type,
    genres,
    tags,
    cast,
    writers,
    trailer,
    language,
  } = req.body;

  movie.title = title;
  movie.storyLine = storyLine;
  movie.tags = tags;
  movie.releseDate = releseDate;
  movie.status = status;
  movie.type = type;
  movie.genres = genres;
  movie.cast = cast;
  movie.trailer = trailer;
  movie.language = language;

  if (director) {
    if (!isValidObjectId(director))
      return sendError(res, "Invalid director id!");
    movie.director = director;
  }

  if (writers) {
    for (let writerId of writers) {
      if (!isValidObjectId(writerId))
        return sendError(res, "Invalid writer id!");
    }

    movie.writers = writers;
  }

  await movie.save();

  res.json({ message: "Movie is updated", movie });
};

exports.updateMovieWithPoster = async (req, res) => {
  const { movieId } = req.params;

  if (!isValidObjectId(movieId)) return sendError(res, "Invalid Movie ID!");

  if (!req.file) return sendError(res, "Movie poster is missing!");

  const movie = await Movie.findById(movieId);
  if (!movie) return sendError(res, "Movie Not Found!", 404);

  const {
    title,
    storyLine,
    director,
    releseDate,
    status,
    type,
    genres,
    tags,
    cast,
    writers,
    trailer,
    language,
  } = req.body;

  movie.title = title;
  movie.storyLine = storyLine;
  movie.tags = tags;
  movie.releseDate = releseDate;
  movie.status = status;
  movie.type = type;
  movie.genres = genres;
  movie.cast = cast;
  movie.trailer = trailer;
  movie.language = language;

  if (director) {
    if (!isValidObjectId(director))
      return sendError(res, "Invalid director id!");
    movie.director = director;
  }

  if (writers) {
    for (let writerId of writers) {
      if (!isValidObjectId(writerId))
        return sendError(res, "Invalid writer id!");
    }

    movie.writers = writers;
  }

  // update poster.
  // removing poster from cloud if there is any.
  const posterID = movie.poster?.public_id;
  if (posterID) {
    const { result } = await cloudinary.uploader.destroy(posterID);
    if (result !== "ok") {
      return sendError(res, "Could not update poster at the moment!");
    }
  }

  // uploading poster
  const {
    secure_url: url,
    public_id,
    responsive_breakpoints,
  } = await cloudinary.uploader.upload(req.file.path, {
    transformation: {
      width: 1280,
      height: 720,
    },
    responsive_breakpoints: {
      create_derived: true,
      max_width: 640,
      max_images: 3,
    },
  });

  const finalPoster = { url, public_id, responsive: [] };

  const { breakpoints } = responsive_breakpoints[0];
  if (breakpoints.length) {
    for (let imgObj of breakpoints) {
      const { secure_url } = imgObj;
      finalPoster.responsive.push(secure_url);
    }
  }

  movie.poster = finalPoster;

  await movie.save();

  res.json({ message: "Movie is updated", movie });
};

exports.removeMovie = async (req, res) => {
  const { movieId } = req.params;

  if (!isValidObjectId(movieId)) return sendError(res, "Invalid Movie ID!");

  const movie = await Movie.findById(movieId);
  if (!movie) return sendError(res, "Movie Not Found!", 404);

  // check if there is poster or not.
  // if yes then we need to remove that.

  const posterId = movie.poster?.public_id;
  if (posterId) {
    const { result } = await cloudinary.uploader.destroy(posterId);
    if (result !== "ok")
      return sendError(res, "Could not remove poster from cloud!");
  }

  // removing trailer
  const trailerId = movie.trailer?.public_id;
  if (!trailerId) return sendError(res, "Could not find trailer in the cloud!");
  const { result } = await cloudinary.uploader.destroy(trailerId, {
    resource_type: "video",
  });
  if (result !== "ok")
    return sendError(res, "Could not remove trailer from cloud!");

  await Movie.findByIdAndDelete(movieId);

  res.json({ message: "Movie removed successfully." });
};

const Actor = require("../models/actor");
const {
  sendError,
  uploadImageToCloud,
  formatActor,
} = require("../utils/helper");
const { isValidObjectId } = require("mongoose");
const cloudinary = require("../cloud");

exports.createActor = async (req, res) => {
  const { name, about, gender } = req.body;
  const { file } = req;

  const newActor = new Actor({ name, about, gender });
  if (file) {
    const { url, public_id } = await uploadImageToCloud(file.path);
    newActor.avatar = { url, public_id };
  }
  await newActor.save();
  res.status(201).json(formatActor(newActor));
};

// update
// Things to consider while updating.
// No.1 - is image file is / avatar is also updating.
// No.2 - if yes then remove old image before uploading new image / avatar.

exports.updateActor = async (req, res) => {
  const { name, about, gender } = req.body;
  const { file } = req;
  const { actorId } = req.params;

  if (!isValidObjectId(actorId)) return sendError(res, "Invalid request!");

  const actor = await Actor.findById(actorId);
  if (!actor) return sendError(res, "Invalid request, record not found!");

  const public_id = actor.avatar?.public_id;

  // remove old image if there was one!
  if (public_id && file) {
    const { result } = await cloudinary.uploader.destroy(public_id);
    if (result !== "ok") {
      return sendError(res, "Could not remove image from cloud!");
    }
  }

  // upload new avatar if there is one!
  if (file) {
    const { url, public_id } = await uploadImageToCloud(file.path);
    actor.avatar = { url, public_id };
  }

  actor.name = name;
  actor.about = about;
  actor.gender = gender;

  await actor.save();

  res.status(201).json(formatActor(actor));
};

exports.removeActor = async (req, res) => {
  const { actorId } = req.params;

  if (!isValidObjectId(actorId)) return sendError(res, "Invalid request!");

  const actor = await Actor.findById(actorId);
  if (!actor) return sendError(res, "Invalid request, record not found!");

  const public_id = actor.avatar?.public_id;

  // remove old image if there was one!
  if (public_id) {
    const { result } = await cloudinary.uploader.destroy(public_id);
    if (result !== "ok") {
      return sendError(res, "Could not remove image from cloud!");
    }
  }

  await Actor.findByIdAndDelete(actorId);

  res.json({ message: "Record removed successfully." });
};

exports.searchActor = async (req, res) => {
  const { query } = req;
  const result = await Actor.find({ $text: { $search: `"${query.name}"` } });

  const actors = result.map((actor) => formatActor(actor));

  res.json(actors);
};

exports.getLatestActors = async (req, res) => {
  const result = await Actor.find().sort({ createdAt: "-1" }).limit(12);

  const actors = result.map((actor) => formatActor(actor));

  res.json(actors);
};

exports.getSingleActor = async (req, res) => {
  const { id } = req.params;

  if (!isValidObjectId(id)) return sendError(res, "Invalid request!");

  const actor = await Actor.findById(id);
  if (!actor) return sendError(res, "Invalid request, actor not found!", 404);
  res.json(formatActor(actor));
};

const jwt = require("jsonwebtoken");
const { sendError } = require("../utils/helper");
const User = require("../models/user");

exports.isAuth = async (req, res, next) => {
  const bearerToken = req.headers?.authorization;
  if (!bearerToken) return sendError(res, "unauthorized access!");

  const token = bearerToken.split(" ")[1];
  if (!token) return sendError(res, "unauthorized access!");

  const decode = jwt.verify(token, process.env.JWT_SECRET);
  if (!decode.userId) {
    return sendError(res, "unauthorized access!");
  }

  const user = await User.findById(decode.userId);
  if (!user) {
    return sendError(res, "unauthorized access!");
  }

  req.user = user;

  next();
};

exports.isAdmin = async (req, res, next) => {
  const { user } = req;
  if (user.role === "admin") next();
  else return sendError(res, "unauthorized access!");
};

exports.errorHandler = (err, req, res, next) => {
  res.status(500).json({ errro: err.message || err });
};

exports.parseData = (req, res, next) => {
  const { trailer, cast, genres, tags, writers } = req.body;

  if (trailer) req.body.trailer = JSON.parse(trailer);
  if (cast) req.body.cast = JSON.parse(cast);
  if (genres) req.body.genres = JSON.parse(genres);
  if (tags) req.body.tags = JSON.parse(tags);
  if (writers) req.body.writers = JSON.parse(writers);

  next();
};

const multer = require("multer");
const storage = multer.diskStorage({});

const imageFileFilter = (req, file, cb) => {
  if (!file.mimetype.startsWith("image")) {
    cb("Supported only image files!", false);
  }
  cb(null, true);
};

const videoFileFilter = (req, file, cb) => {
  if (!file.mimetype.startsWith("video")) {
    cb("Supported only image files!", false);
  }
  cb(null, true);
};

exports.uploadImage = multer({ storage, fileFilter: imageFileFilter });
exports.uploadVideo = multer({ storage, fileFilter: videoFileFilter });

const { isValidObjectId } = require("mongoose");
const PasswordResetToken = require("../models/passwordResetToken");
const { sendError } = require("../utils/helper");
exports.isValidPassResetToken = async (req, res, next) => {
  const { token, userId } = req.body;

  if (!token.trim() || !isValidObjectId(userId))
    return sendError(res, "Invalid request!");

  const resetToken = await PasswordResetToken.findOne({ owner: userId });
  if (!resetToken)
    return sendError(res, "Unauthorized access, invalid request!");

  const matched = await resetToken.compareToken(token);
  if (!matched) return sendError(res, "Unauthorized access, invalid request!");

  req.resetToken = resetToken;
  next();
};

const { check, validationResult } = require("express-validator");
const { isValidObjectId } = require("mongoose");
const genres = require("../utils/genres");

exports.userValidtor = [
  check("name").trim().not().isEmpty().withMessage("Name is missing!"),
  check("email").normalizeEmail().isEmail().withMessage("Email is invalid!"),
  check("password")
    .trim()
    .not()
    .isEmpty()
    .withMessage("Password is missing!")
    .isLength({ min: 8, max: 20 })
    .withMessage("Password must be 8 to 20 characters long!"),
];

exports.validatePassword = [
  check("newPassword")
    .trim()
    .not()
    .isEmpty()
    .withMessage("Password is missing!")
    .isLength({ min: 8, max: 20 })
    .withMessage("Password must be 8 to 20 characters long!"),
];

exports.signInValidator = [
  check("email").normalizeEmail().isEmail().withMessage("Email is invalid!"),
  check("password").trim().not().isEmpty().withMessage("Password is missing!"),
];

exports.actorInfoValidator = [
  check("name").trim().not().isEmpty().withMessage("Actor name is missing!"),
  check("about")
    .trim()
    .not()
    .isEmpty()
    .withMessage("About is a required field!"),
  check("gender")
    .trim()
    .not()
    .isEmpty()
    .withMessage("Gender is a required field!"),
];

exports.validateMovie = [
  check("title").trim().not().isEmpty().withMessage("Movie title is missing!"),
  check("storyLine")
    .trim()
    .not()
    .isEmpty()
    .withMessage("Storyline is important!"),
  check("language").trim().not().isEmpty().withMessage("Language is missing!"),
  check("releseDate").isDate().withMessage("Relese date is missing!"),
  check("status")
    .isIn(["public", "private"])
    .withMessage("Movie status must be public or private!"),
  check("type").trim().not().isEmpty().withMessage("Movie type is missing!"),
  check("genres")
    .isArray()
    .withMessage("Genres must be an array of strings!")
    .custom((value) => {
      for (let g of value) {
        if (!genres.includes(g)) throw Error("Invalid genres!");
      }

      return true;
    }),
  check("tags")
    .isArray({ min: 1 })
    .withMessage("Tags must be an array of strings!")
    .custom((tags) => {
      for (let tag of tags) {
        if (typeof tag !== "string")
          throw Error("Tags must be an array of strings!");
      }

      return true;
    }),
  check("cast")
    .isArray()
    .withMessage("Cast must be an array of objects!")
    .custom((cast) => {
      for (let c of cast) {
        if (!isValidObjectId(c.actor))
          throw Error("Invalid cast id inside cast!");
        if (!c.roleAs?.trim()) throw Error("Role as is missing inside cast!");
        if (typeof c.leadActor !== "boolean")
          throw Error(
            "Only accepted boolean value inside leadActor inside cast!"
          );

        return true;
      }
    }),
  check("trailer")
    .isObject()
    .withMessage("trailer must be an object with url and public_id")
    .custom(({ url, public_id }) => {
      try {
        const result = new URL(url);
        if (!result.protocol.includes("http"))
          throw Error("Trailer url is invalid!");

        const arr = url.split("/");
        const publicId = arr[arr.length - 1].split(".")[0];

        if (public_id !== publicId)
          throw Error("Trailer public_id is invalid!");

        return true;
      } catch (error) {
        throw Error("Trailer url is invalid!");
      }
    }),
  // check("poster").custom((_, { req }) => {
  //   if (!req.file) throw Error("Poster file is missing!");

  //   return true;
  // }),
];

exports.validate = (req, res, next) => {
  const error = validationResult(req).array();
  if (error.length) {
    return res.json({ error: error[0].msg });
  }

  next();
};

const mongoose = require("mongoose");

const actorSchema = mongoose.Schema(
  {
    name: {
      type: String,
      trim: true,
      required: true,
    },
    about: {
      type: String,
      trim: true,
      required: true,
    },
    gender: {
      type: String,
      trim: true,
      required: true,
    },
    avatar: {
      type: Object,
      url: String,
      public_id: String,
    },
  },
  { timestamps: true }
);

actorSchema.index({ name: "text" });

module.exports = mongoose.model("Actor", actorSchema);

const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const emailVerificationTokenSchema = mongoose.Schema({
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  token: {
    type: String,
    required: true,
  },
  createAt: {
    type: Date,
    expires: 3600,
    default: Date.now(),
  },
});

emailVerificationTokenSchema.pre("save", async function (next) {
  if (this.isModified("token")) {
    this.token = await bcrypt.hash(this.token, 10);
  }

  next();
});

emailVerificationTokenSchema.methods.compareToken = async function (token) {
  const result = await bcrypt.compare(token, this.token);
  return result;
};

module.exports = mongoose.model(
  "EmailVerificationToken",
  emailVerificationTokenSchema
);

const mongoose = require("mongoose");
const genres = require("../utils/genres");

const movieSchema = mongoose.Schema(
  {
    title: {
      type: String,
      trim: true,
      required: true,
    },
    storyLine: {
      type: String,
      trim: true,
      required: true,
    },
    director: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Actor",
    },
    releseDate: {
      type: Date,
      required: true,
    },
    status: {
      type: String,
      required: true,
      enum: ["public", "private"],
    },
    type: {
      type: String,
      required: true,
    },
    genres: {
      type: [String],
      required: true,
      enum: genres,
    },
    tags: {
      type: [String],
      required: true,
    },
    cast: [
      {
        actor: { type: mongoose.Schema.Types.ObjectId, ref: "Actor" },
        roleAs: String,
        leadActor: Boolean,
      },
    ],
    writers: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Actor",
      },
    ],
    poster: {
      type: Object,
      url: { type: String, required: true },
      public_id: { type: String, required: true },
      responsive: [URL],
      required: true,
    },
    trailer: {
      type: Object,
      url: { type: String, required: true },
      public_id: { type: String, required: true },
      required: true,
    },
    reviews: [{ type: mongoose.Schema.Types.ObjectId, ref: "Review" }],
    language: {
      type: String,
      required: true,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Movie", movieSchema);

const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const passwordReserTokenSchema = mongoose.Schema({
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  token: {
    type: String,
    required: true,
  },
  createAt: {
    type: Date,
    expires: 3600,
    default: Date.now(),
  },
});

passwordReserTokenSchema.pre("save", async function (next) {
  if (this.isModified("token")) {
    this.token = await bcrypt.hash(this.token, 10);
  }

  next();
});

passwordReserTokenSchema.methods.compareToken = async function (token) {
  const result = await bcrypt.compare(token, this.token);
  return result;
};

module.exports = mongoose.model("PasswordResetToken", passwordReserTokenSchema);

const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = mongoose.Schema({
  name: {
    type: String,
    trim: true,
    required: true,
  },
  email: {
    type: String,
    trim: true,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  isVerified: {
    type: Boolean,
    required: true,
    default: false,
  },
  role: {
    type: String,
    required: true,
    default: "user",
    enum: ["admin", "user"],
  },
});

userSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    this.password = await bcrypt.hash(this.password, 10);
  }

  next();
});

userSchema.methods.comparePassword = async function (password) {
  const result = await bcrypt.compare(password, this.password);
  return result;
};

module.exports = mongoose.model("User", userSchema);

const express = require("express");
const {
  create,
  verifyEmail,
  resendEmailVerificationToken,
  forgetPassword,
  sendResetPasswordTokenStatus,
  resetPassword,
  signIn,
} = require("../controllers/user");
const { isValidPassResetToken } = require("../middlewares/user");
const {
  userValidtor,
  validate,
  validatePassword,
  signInValidator,
} = require("../middlewares/validator");

const router = express.Router();

router.post("/create", userValidtor, validate, create);
router.post("/sign-in", signInValidator, validate, signIn);
router.post("/verify-email", verifyEmail);
router.post("/resend-email-verification-token", resendEmailVerificationToken);
router.post("/forget-password", forgetPassword);
router.post(
  "/verify-pass-reset-token",
  isValidPassResetToken,
  sendResetPasswordTokenStatus
);
router.post(
  "/reset-password",
  validatePassword,
  validate,
  isValidPassResetToken,
  resetPassword
);

module.exports = router;

const express = require("express");
const {
  uploadTrailer,
  createMovie,
  updateMovieWithoutPoster,
  updateMovieWithPoster,
  removeMovie,
} = require("../controllers/movie");
const { isAuth, isAdmin } = require("../middlewares/auth");
const { parseData } = require("../middlewares/helper");
const { uploadVideo, uploadImage } = require("../middlewares/multer");
const { validateMovie, validate } = require("../middlewares/validator");
const router = express.Router();

router.post(
  "/upload-trailer",
  isAuth,
  isAdmin,
  uploadVideo.single("video"),
  uploadTrailer
);
router.post(
  "/create",
  isAuth,
  isAdmin,
  uploadImage.single("poster"),
  parseData,
  validateMovie,
  validate,
  createMovie
);
router.patch(
  "/update-movie-without-poster/:movieId",
  isAuth,
  isAdmin,
  // parseData,
  validateMovie,
  validate,
  updateMovieWithoutPoster
);
router.patch(
  "/update-movie-with-poster/:movieId",
  isAuth,
  isAdmin,
  uploadImage.single("poster"),
  parseData,
  validateMovie,
  validate,
  updateMovieWithPoster
);
router.delete("/:movieId", isAuth, isAdmin, removeMovie);

module.exports = router;

const express = require("express");
const {
  createActor,
  updateActor,
  removeActor,
  searchActor,
  getLatestActors,
  getSingleActor,
} = require("../controllers/actor");
const { isAuth, isAdmin } = require("../middlewares/auth");
const { uploadImage } = require("../middlewares/multer");
const { actorInfoValidator, validate } = require("../middlewares/validator");
const router = express.Router();

router.post(
  "/create",
  isAuth,
  isAdmin,
  uploadImage.single("avatar"),
  actorInfoValidator,
  validate,
  createActor
);

router.post(
  "/update/:actorId",
  isAuth,
  isAdmin,
  uploadImage.single("avatar"),
  actorInfoValidator,
  validate,
  updateActor
);

router.delete("/:actorId", isAuth, isAdmin, removeActor);
router.get("/search", isAuth, isAdmin, searchActor);
router.get("/latest-uploads", isAuth, isAdmin, getLatestActors);
router.get("/single/:id", getSingleActor);
module.exports = router;

const nodemailer = require("nodemailer");

exports.generateOTP = (otp_length = 6) => {
  let OTP = "";
  for (let i = 1; i <= otp_length; i++) {
    const randomVal = Math.round(Math.random() * 9);
    OTP += randomVal;
  }

  return OTP;
};

exports.generateMailTransporter = () =>
  nodemailer.createTransport({
    host: "smtp.mailtrap.io",
    port: 2525,
    auth: {
      user: process.env.MAIL_TRAP_USER,
      pass: process.env.MAIL_TRAP_PASS,
    },
  });

const crypto = require("crypto");
const cloudinary = require("../cloud");

exports.sendError = (res, error, statusCode = 401) => {
  res.status(statusCode).json({ error });
};

exports.generateRandomByte = () => {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(30, (err, buff) => {
      if (err) reject(err);
      const buffString = buff.toString("hex");

      console.log(buffString);
      resolve(buffString);
    });
  });
};

exports.uploadImageToCloud = async (file) => {
  const { secure_url: url, public_id } = await cloudinary.uploader.upload(
    file,
    { gravity: "face", height: 500, width: 500, crop: "thumb" }
  );

  return { url, public_id };
};

exports.formatActor = (actor) => {
  const { name, gender, about, _id, avatar } = actor;
  return {
    id: _id,
    name,
    about,
    gender,
    avatar: avatar?.url,
  };
};

const genres = [
  "Action",
  "Adventure",
  "Animation",
  "Biography",
  "Comedy",
  "Crime",
  "Documentary",
  "Drama",
  "Family",
  "Fantasy",
  "Fiction",
  "Film-Noir",
  "Game Show",
  "History",
  "Horror",
  "Music",
  "Musical",
  "Mystery",
  const express = require("express");
require("express-async-errors");
const morgan = require("morgan");
const { errorHandler } = require("./middlewares/error");
require("dotenv").config();
require("./db");
const userRouter = require("./routes/user");
const actorRouter = require("./routes/actor");
const movieRouter = require("./routes/movie");

const app = express();
app.use(express.json());
app.use(morgan("dev"));
app.use("/api/user", userRouter);
app.use("/api/actor", actorRouter);
app.use("/api/movie", movieRouter);

app.use(errorHandler);

// app.post(
//   "/sign-in",
//   (req, res, next) => {
//     const { email, password } = req.body;
//     if (!email || !password)
//       return res.json({ error: "email/password missing!" });
//     next();
//   },
//   (req, res) => {
//     res.send("<h1>Hello I am about page</h1>");
//   }
// );

app.listen(8000, () => {
  console.log("the port is listening on port 8000");
});

const movieInfo = {
  title: "some title",
  storyLine: "little bit about the movie",
  director: "123456",
  releseDate: "07-01-2022",
  status: "private",
  type: "Movie",
  genres: ["Sci-fi", "Action"],
  tags: ["action", "movie", "hollywood"],
  cast: [{ id: "kfd2354po", roleAs: "John Doe", leadActor: true }],
  writers: ["456789sfa", "fsda589745"],
  poster: File,
  trailer: { url: "https://", public_id: "fkasdfi456" },
  language: "English",
};

// Ended at 6:20 6-2-2022
  "News",
  "Reality TV",
  "Romance",
  "Sci-Fi",
  "Superhero",
  "Sport",
  "Talk Show",
  "Thriller",
  "War",
  "Western",
];

module.exports = genres;

const express = require("express");
require("express-async-errors");
const morgan = require("morgan");
const { errorHandler } = require("./middlewares/error");
require("dotenv").config();
require("./db");
const userRouter = require("./routes/user");
const actorRouter = require("./routes/actor");
const movieRouter = require("./routes/movie");

const app = express();
app.use(express.json());
app.use(morgan("dev"));
app.use("/api/user", userRouter);
app.use("/api/actor", actorRouter);
app.use("/api/movie", movieRouter);

app.use(errorHandler);

// app.post(
//   "/sign-in",
//   (req, res, next) => {
//     const { email, password } = req.body;
//     if (!email || !password)
//       return res.json({ error: "email/password missing!" });
//     next();
//   },
//   (req, res) => {
//     res.send("<h1>Hello I am about page</h1>");
//   }
// );

app.listen(8000, () => {
  console.log("the port is listening on port 8000");
});

const movieInfo = {
  title: "some title",
  storyLine: "little bit about the movie",
  director: "123456",
  releseDate: "07-01-2022",
  status: "private",
  type: "Movie",
  genres: ["Sci-fi", "Action"],
  tags: ["action", "movie", "hollywood"],
  cast: [{ id: "kfd2354po", roleAs: "John Doe", leadActor: true }],
  writers: ["456789sfa", "fsda589745"],
  poster: File,
  trailer: { url: "https://", public_id: "fkasdfi456" },
  language: "English",
};

// Ended at 6:20 6-2-2022
