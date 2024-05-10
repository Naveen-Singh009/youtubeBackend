import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken" // jwt is bearer token .. jo usko bear krta hai usko sahi maan lete hain
import bcrypt from "bcrypt"

const userSchema = new Schema(
    {
        username: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
            index: true, // this is used for optimized searching (searchable enabled with otimized )
        },
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
        },
        fullName: {
            type: String,
            required: true,
            trim: true,
            index: true
        },
        avatar: {
            type: String,//cloudinary url
            required: true,
        },
        coverImage: {
            type: String,// cloudinary url
        },
        watchHistory: [
            {
                type: Schema.Types.ObjectId,
                ref: "Video"
            }
        ],
        password: {
            type: String,
            required: [true, 'Password is required'], // we can give a custom message with true field  
        },
        refreshToken: {
            type: String
        }
    },
    {
        timestamps: true
    }
)

//does not write arrow fun here because arrow fun does not have reference of this keyword
userSchema.pre("save", async function (next) {
    if(!this.isModified("password")) return next();
    this.password = await bcrypt.hash(this.password, 10)
    next()
} )

userSchema.methods.isPasswordCorrect = async function (password){
    return await bcrypt.compare(password, this.password) // it will return true or false
}

userSchema.methods.generateAccessToken = function () {
    return jwt.sign(
        {
            _id : this._id,
            email: this.email,
            username : this.username,
            fullName : this.fullName
        }, 
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }
    )
    
}

userSchema.methods.generateRefreshToken = function () {
    return jwt.sign(
        {
            _id : this._id
        }, 
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}

export const User = mongoose.model("User", userSchema)