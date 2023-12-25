const ErrorHandler = require("../utils/errorhandler");
const catchAsyncError = require("../middleware/catchAsyncError");
const User = require("../models/userModel");
const sendToken = require("../utils/jwtToken");
const sendEmail = require("../utils/sendEmail");
const { response } = require("express");
const crypto = require("crypto");

//Register a user

exports.registerUser = catchAsyncError(async (req, res, next) => {

    const { name, email, password } = req.body;

    const user = await User.create({
        name, email, password,
        avatar: {
            public_id: "this is a sample id",
            url: "profilepicUrl"
        }
    });

    sendToken(user, 201, res);
});

//Login user

exports.loginUser = catchAsyncError(async (req, res, next) => {

    const { email, password } = req.body;
 
    if (!email || !password) {
        return next(new ErrorHandler("Please Enter Email & Password", 400))
    }

    const user = await User.findOne({ email }).select("+password");

    if (!user) {
        return next(new ErrorHandler("Invalid Email or password", 401));
    }

    const isPasswordMatched = await user.comparePassword(password);

    if (!isPasswordMatched) {
        return next(new ErrorHandler("Invalid Email or password", 401));
    }

    sendToken(user, 200, res);
});

//Logout user

exports.logout = catchAsyncError(async (req, res, next) => {

    res.cookie("token", null, {
        expires: new Date(Date.now()),
        httpOnly: true,
    })
    res.status(200).json({
        success: true,
        message: "Logged out",
    })
})

//Forgot password

exports.forgotPassword = catchAsyncError(async (req, res, next) => {

    const user = await User.findOne({ email: req.body.email });

    if (!user) {
        return next(new ErrorHandler("User not found", 404))
    }

    //Get reset password token
    const resetToken = user.getResetPasswordToken();

    await user.save({ validateBeforeSave: false });

    const resetPasswordUrl = `${req.protocol}://${req.get("host")}/api/password/reset/${resetToken}`;

    const message = `Your password reset token is :- \n\n ${resetPasswordUrl} \n\nIf you have not requested this email then,please ignore it`;

    try {

        await sendEmail({
            email: user.email,
            subject: `Ecommerce Password Recovery`,
            message,

        });

        res.status(200).json({
            success: true,
            message: `Email sent to ${user.email} successfully`,
        })

    } catch (error) {

        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;

        await user.save({ validateBeforeSave: false });

        return next(new ErrorHandler(error.message, 500));

    }
});

//Reset password

exports.resetPassword = catchAsyncError(async (req, res, next) => {

    //Create token hash

    const resetPasswordToken = crypto
        .createHash("sha256")
        .update(req.params.token)
        .digest("hex");

    const user = await User.findOne({
        resetPasswordToken,
        resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
        return next(new ErrorHandler("Reset Password Token is invalid or has been expired", 400));
    }

    if (req.body.password !== req.body.confirmPassword) {

        return next(new ErrorHandler("Password Does not Match", 400));
    }

    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save();

    sendToken(user, 200, res);

});

//Get user information

exports.getUserDetail = catchAsyncError(async (req, res, next) => {
    const user = await User.findById(req.user.id);

    res.status(200).json({
        success: true,
        user,
    });
});

//Update user password

exports.updatePassword = catchAsyncError(async (req, res, next) => {
    const user = await User.findById(req.user.id).select("+password");

    const isPasswordMatched = await user.comparePassword(req.body.oldPassword);

    if (!isPasswordMatched) {
        return next(new ErrorHandler("Old Password is incorrect", 400));
    }

    if (req.body.newPassword !== req.body.confirmPassword) {
        return next(new ErrorHandler("Password does not match", 400));
    }

    user.password = req.body.newPassword;

    await user.save();

    sendToken(user, 200, res);

});


//Update user profile

exports.updateProfile = catchAsyncError(async (req, res, next) => {

    const { name, email } = req.body;

    if (!name || !email) {
        return next(new ErrorHandler("Name and Email are both required", 400));
    }

    const newUserData = {
        name,
        email,
    };

    const user = await User.findByIdAndUpdate(req.user.id, newUserData, {
        new: true,
        runValidators: true,
        useFindAndModify: false,
    });

    res.status(200).json({
        success: true,
    });

});

//Get all users by admin

exports.getAllUser = catchAsyncError(async (req, res, next) => {

    const users = await User.find();

    res.status(200).json({
        success: true,
        users

    })
});

//Get Single User by admin

exports.getSingleUser = catchAsyncError(async (req, res, next) => {

    const user = await User.findById(req.params.id);

    if (!user) {
        return next(new ErrorHandler(`User does not exist with id: ${req.params.id}`));
    }

    res.status(200).json({
        success: true,
        user

    })
});

//Update user role by admin

exports.updateUserRole = catchAsyncError(async (req, res, next) => {
    const { name, email, role } = req.body;

    if (!name || !email || !role) {
        return next(new ErrorHandler("All fields are required", 400));
    }

    const newUserData = {
        name,
        email,
        role
    };



    const user = await User.findByIdAndUpdate(req.params.id, newUserData, {
        new: true,
        runValidators: true,
        useFindAndModify: false,
    });

    res.status(200).json({
        success: true,
    });

});

// Delete user by admin

exports.deleteUser = catchAsyncError(async (req, res, next) => {

    const user = await User.findById(req.params.id);

    if (!user) {
        return next(new ErrorHandler(`User does not exist with id: ${req.params.id}`));
    }

    await user.deleteOne();

    res.status(200).json({
        success: true,
        message: "User deleted successfully"
    });

});





