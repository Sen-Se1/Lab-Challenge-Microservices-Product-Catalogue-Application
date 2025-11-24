const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");
const createToken = require("../utils/createToken");
const ApiError = require("../utils/apiError");
const User = require("../models/userModel");

// @desc    Register
// @route   Post /api/v1/auth/register
// @access  Public
exports.register = asyncHandler(async (req, res, next) => {
  // 1) hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);

  // 2) Create user with all fields
  const user = await User.create({
    email: req.body.email,
    password: hashedPassword,
    profile: {
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      phone: req.body.phone,
      avatar: req.body.avatar,
      dateOfBirth: req.body.dateOfBirth,
    },
    address: {
      street: req.body.street,
      city: req.body.city,
      state: req.body.state,
      country: req.body.country,
      zipCode: req.body.zipCode,
    },
    lastLogin: Date.now(),
  });

  // 3) Generate token
  const token = createToken(user._id);

  // 4) Delete password from response
  delete user._doc.password;

  // 5) send response to client side
  res.status(201).json({ data: user, token });
});

// @desc    Login
// @route   POST /api/v1/auth/login
// @access  Public
exports.login = asyncHandler(async (req, res, next) => {
  // 1) check if password and email in the body (validation)
  // 2) check if user exist & check if password is correct
  const user = await User.findOne({ email: req.body.email });

  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return next(new ApiError("Incorrect email or password", 401));
  }

  // 3) Check if user is active
  if (!user.isActive) {
    return next(new ApiError("Your account has been deactivated", 403));
  }

  // 4) Update last login
  user.lastLogin = Date.now();
  await user.save();

  // 5) generate token
  const token = createToken(user._id);

  // 6) Delete password from response
  delete user._doc.password;

  // 7) send response to client side
  res.status(200).json({ data: user, token });
});

// @desc    Forgot password
// @route   POST /api/v1/auth/forgotPassword
// @access  Public
exports.forgotPassword = asyncHandler(async (req, res, next) => {
  // 1) Get user by email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(
      new ApiError(
        `There is no user with this email address: ${req.body.email}`,
        404
      )
    );
  }

  // 2) Generate reset token
  const resetToken = crypto.randomBytes(32).toString("hex");
  const hashedResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // 3) Save token to user
  user.passwordResetToken = hashedResetToken;
  user.passwordResetTokenExpires = Date.now() + 5 * 60 * 1000;
  await user.save();

  // 4) Determine frontend URL from req.body.client or use default
  const client = req.body.client || "public";
  const frontendUrls = {
    admin: process.env.ADMIN_FRONTEND_URL || "http://localhost:4200",
    public: process.env.PUBLIC_FRONTEND_URL || "http://localhost:3000",
  };

  const frontendUrl = frontendUrls[client] || frontendUrls.public;
  const resetUrl = `${frontendUrl}/reset-password/${resetToken}`;

  // 5) Create email message
  const message = `Forgot your password? Click here to reset: ${resetUrl}`;

  try {
    // 6) Send email
    await sendEmail({
      email: user.email,
      subject: "Password Reset Request",
      message,
    });
  } catch (err) {
    // 7) Handle email error - clear reset token
    user.passwordResetToken = undefined;
    user.passwordResetTokenExpires = undefined;
    await user.save();
    return next(new ApiError("Email sending failed. Try again later!", 500));
  }

  // 8) Send success response
  res.status(200).json({
    message: "Password reset link sent to your email",
  });
});

// @desc    Reset password
// @route   PUT /auth/resetPassword/:token
// @access  Public
exports.resetPassword = asyncHandler(async (req, res, next) => {
  // 1) Get user based on reset token
  const hashedResetToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  const user = await User.findOne({
    passwordResetToken: hashedResetToken,
    passwordResetTokenExpires: { $gt: Date.now() },
  });

  if (!user) {
    return next(new ApiError("Token is invalid or has expired", 400));
  }
  // 2) hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);

  user.password = hashedPassword;
  user.passwordResetToken = undefined;
  user.passwordResetTokenExpires = undefined;
  user.passwordChangedAt = Date.now();

  await user.save();

  const token = createToken(user._id);

  delete user._doc.password;

  res.status(200).json({
    data: user,
    token,
    message: "Your password has been successfully reset",
  });
});

// @desc    Get current user
// @route   GET /api/v1/auth/me
// @access  Private
exports.getMe = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user._id);
  delete user._doc.password;
  res.status(200).json({ data: user });
});

// @desc    Update user profile
// @route   PUT /user/:id
// @access  Private
exports.updateMe = asyncHandler(async (req, res, next) => {
  // 1) Create filtered object to prevent updating restricted fields
  const filteredBody = {};
  const allowedFields = ["profile", "address"];

  allowedFields.forEach((field) => {
    if (req.body[field]) {
      filteredBody[field] = req.body[field];
    }
  });

  // 2) Update user
  const updatedUser = await User.findByIdAndUpdate(req.user._id, filteredBody, {
    new: true,
    runValidators: true,
  });

  delete updatedUser._doc.password;

  res.status(200).json({ data: updatedUser });
});

// @desc    Update logged user password
// @route   PUT /user/password/:id
// @access  Private
exports.updatePassword = asyncHandler(async (req, res, next) => {
  // 1) hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);

  const newData = {
    password: hashedPassword,
    passwordChangedAt: Date.now(),
  };

  // Build query
  const user = await User.findOneAndUpdate({ _id: req.user._id }, newData, {
    new: true,
  });

  // 2) Generate token
  const token = createToken(user._id);

  // Delete password from response
  delete user._doc.password;

  res.status(200).json({ data: user, token });
});

// @desc    Delete user (deactivate)
// @route   DELETE /user/delete-me
// @access  Private
exports.deleteMe = asyncHandler(async (req, res, next) => {
  await User.findByIdAndUpdate(req.user._id, { isActive: false });

  res.status(204).json({
    status: "success",
    data: null,
  });
});

// @desc    Get user by ID (Admin only)
// @route   GET /user/:id
// @access  Private/Admin
exports.getUser = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    return next(new ApiError(`No user found with that ID : ${req.params.id}`, 404));
  }
  delete user._doc.password;
  res.status(200).json({ data: user });
});

// @desc    Get all users (Admin only)
// @route   GET /user
// @access  Private/Admin
exports.getAllUsers = asyncHandler(async (req, res, next) => {
  const users = await User.find();

  res.status(200).json({
    results: users.length,
    data: users,
  });
});

// @desc    Update user (Admin only)
// @route   Patch /user/:id
// @access  Private/Admin
exports.updateUser = asyncHandler(async (req, res, next) => {
  const user = await User.findByIdAndUpdate(
    req.params.id,
    req.body,
    { new: true, runValidators: true }
  );
  
  if (!user) {
    return next(new ApiError(`No user found with that ID : ${req.params.id}`, 404));
  }
  
  res.status(200).json({ data: user });
});

// @desc    Delete user (Admin only)
// @route   DELETE /user/:id
// @access  Private/Admin
exports.deleteUser = asyncHandler(async (req, res, next) => {
  const user = await User.findByIdAndDelete(req.params.id);
  
  if (!user) {
    return next(new ApiError(`No user found with that ID : ${req.params.id}`, 404));
  }
  
  res.status(204).json({
    status: 'success',
    data: null
  });
});