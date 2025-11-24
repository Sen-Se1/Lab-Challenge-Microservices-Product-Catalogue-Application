const express = require("express");
const router = express.Router();
// const {
//   loginValidator,
//   registerValidator,
//   resetPasswordValidator,
//   getProfileValidator,
//   updateProfileValidator,
//   updateProfilePwdValidator,
// } = require("../utils/validators/userValidator");
// const { protect, isProfileOwner } = require("../middlewares/authMiddleware");
const {
  login,
  register,
  forgotPassword,
  resetPassword,
  getProfile,
  updateProfile,
  updateProfilePwd,
} = require("../controllers/userController");

router.post("/auth/login", login);
router.post("/auth/register", register);
router.post('/auth/forgotPassword', forgotPassword);
router.put('/auth/resetPassword/:token', resetPassword);

// only login user is allowed
// router.get(
//   "/:id",
//   protect,
//   getProfileValidator,
//   isProfileOwner,
//   getProfile
// );
// router.put(
//   "/:id",
//   protect,
//   isProfileOwner,
//   updateProfileValidator,
//   updateProfile
// );
// router.put(
//   "/password/:id",
//   protect,
//   isProfileOwner,
//   updateProfilePwdValidator,
//   updateProfilePwd
// );

module.exports = router;
