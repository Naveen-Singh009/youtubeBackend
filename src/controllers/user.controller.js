import {asyncHandler} from "../utils/asyncHandler.js"
import {ApiError} from "../utils/ApiError.js"
import {User} from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"



const registerUser = asyncHandler ( async(req, res) => {
    // get user details from frontend
    // validation - not empty
    // check if user already exist 
    // check for images , check for avatar
    // upload them to cloudinary
    // create user object - create entry in db
    // remove password and refresh token fiels from response 
    // check for response user creation 
    // return response

    const {email, password, fullName, username} = req.body 
    console.log(email);

    // if(fullName === "" ){
    //     throw new ApiError(400, "fullname is required")
    // }
    if (
        [fullName, email, username, password]. some((field) => field?.trim() === "" )
    ) {
        throw new ApiError(400, "all fields are required")
    }

    const existedUser  = await User.findOne({
        $or : [{username}, {email}]
    })

    if(existedUser){
        throw new ApiError(409, "User with username or email already exist")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    const coverImageLocalPath = req.files?.coverImage[0]?.path;

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar){
        throw new ApiError(400, "Avatar file is required")
    }

    const user = await User.create({
        fullName,
        avatar : avatar.url,
        coverImage: coverImage?.url || "",
        email, 
        password,
        username : username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!createdUser){
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User Registered Successfully")
    )
})


export {
    registerUser
}