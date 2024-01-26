import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";    
import { User } from "../models/user.models.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt, { decode } from "jsonwebtoken"


// we are gonna use tokens very more so we are going to make a method(or function) to generate them
const generateAccessAndRefreshTokens = async(userId)=>{
    try {
        const user = await User.findById(userId)
       const accessToken =  user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

       user.refreshToken = refreshToken
       await user.save({validateBeforeSave:false})

       return {accessToken,refreshToken}
    } catch (error) {
        throw new ApiError(500,"something went wrong while generate access and refresh token")
    }
}

const registerUser = asyncHandler( async (req,res) =>{
//    return res.status(200).json({
//         message:"ok , chai aur code"
//     })


  // steps to get user details in backend
    // get user details from frontend
    // validation - not empty
    // check if user already exists - by username or email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refreshtoken feed from response
    // check for user creation
    // return response else send error


    const {fullname,email,username,password} = req.body
    console.log("email",email);
    // if(fullname ===""){
    //     throw new ApiError(400,"full name is required")
    // }// and one by one OR----

    // validation - not empty
    if(
        [fullname,email,username,password].some((field)=>field?.trim()==="")
    ){
        throw new ApiError(400,"All fields are required")

    }

        // check if user already exists - by username or email
   const existedUser = await User.findOne({
        $or:[{ username },{ email }]
    })
    if(existedUser){
        throw new ApiError(409,"User with email or username already exists")
    }

     // check for images, check for avatar
   const avatarLocalPath =  req.files?.avatar[0]?.path;
//  const coverImageLocalPath =  req.files?.coverImage[0]?.path;

// let avatarLocalPath;
// if(req.files && Array.isArray(req.files.avatar) && req.files.avatarImage.length >0){
//     avatarLocalPath = req.files.coverImage[0].path
// }
if(!avatarLocalPath){
    throw new ApiError(400,"avatar file is required")
 }
 


let coverImageLocalPath;
if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
coverImageLocalPath = req.files.coverImage[0].path
}

 // upload them to cloudinary, avatar
 const avatar =  await uploadOnCloudinary(avatarLocalPath)
 const coverImage = await uploadOnCloudinary(coverImageLocalPath);  
 
 if(!avatar){
    throw new ApiError(400,"avatar file is required")
 }


 //create user object - create entry in db
 const user = await User.create({
    fullname,
    avatar:avatar.url,
    coverImage:coverImage?.url || "",
    email,
    password,
    username:username.toLowerCase(),
 })


 // remove password and refreshtoken feed from response
const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
)

// check for user creation
if(!createdUser){
    throw new ApiError(500,"something went wrong while registering the user")
}


// return response else send error
return res.status(201).json(
    new ApiResponse(200,createdUser,"User registered successfully !! ")
)
 

})
const loginUser = asyncHandler (async(req,res)=>{
    //1. req body -> data
    // 2. username based login or email based login
    // 3. find the user
    //4. if user found password check
    //5. if password right - send access and refresh toke to the user
    //6.send cookies and send response that user is successfully login

    // 1. take data from req.body
    const {email,username, password} = req.body
    //.check for username OR password
    if(!(username || email)){
        throw new ApiError(400,"username and password required")
    }
    //3. check for username in database
  const user = await User.findOne({
        $or:[{username},{email}]
    })
    if(!user){
        throw new ApiError(404,"User does not exist")
    }
    
   //4. check password
   const isPasswordValid = await user.isPasswordCorrect(password)
 
   if(!isPasswordValid){
    throw new ApiError(401,'Invalid user credentials')
   }
   
   //5. make access and refresh token
     // we had already made a method(or function) to generate access token and refresh token
 const {accessToken,refreshToken} =   await generateAccessAndRefreshTokens(user._id)

 //6. send information in cookies
 const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

// send cookies
const options = {
   httpOnly:true,
   secure:true
}

return res.status(200)
.cookie("accessToken", accessToken,options)
.cookie("refreshToken", refreshToken,options)
.json(
    new ApiResponse(
        200,{
            user:loggedInUser,
            accessToken,refreshToken
        },
        "User logged in successfully"

    )
)
})

// how to user will logout 
 const logoutUser = asyncHandler(async(req,res) => {
    // 1. clear the cookies
    // after the middleware operation now we have access to user
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:{
                refreshToken: undefined
            }
        },
        {
            new:true 
        }
    )
    const options = {
        httpOnly : true,
        secure:true
    }

    return res.status(200).clearCookie("accessToken",options).clearCookie("refreshToken",options).json(new ApiResponse(200,{},"User logged out"))

 })

 const refreshAccessToken = asyncHandler(async (req,res)=>{
    // how we are going to refresh the access token using refresh token, becoz that whats actually happens the user will get access through only access token and refresh token refresh the access token 
    const incomingRefreshToken = req.coookies.refreshToken || req.body.refreshToken // we are taking incoming refresh token from user and will match with existing refresh token in the database , user might using the mobild application so we are also taking refresh token from req.body 


    // now what if there is no incoming refresh token, then we will throw the error 
    if(!incomingRefreshToken){
        throw new ApiError(401,"unauthorized request")
    }

    // now we will verify the incoming refresh token with jwt
   try {
    const decodedToken =  jwt.verify(
         incomingRefreshToken,process.env.REFRESH_TOKEN_SECRET,
 
     )
 
     const user = await User.findById(decodedToken?._id)
     
     if(!user){
         throw new ApiError(401,"Invalid refresh token")
     }
 
     // now match two tokens
     if(incomingRefreshToken !== user?.refreshToken){
         throw new ApiError(401,"refresh token expired or used")
     }
 
    const options = {
     httpOnly:true,
     secure : true
    }
  const {accessToken,newrefreshToken} = await generateAccessAndRefreshTokens(user._id)
   return res.status(200).cookie("accessToken",accessToken,options).cookie("refreshToken",newrefreshToken, options).json(
     new ApiResponse(
         200,
         {accessToken,refreshToken:newrefreshToken},
         "Access token refreshed"
     )
   )
   } catch (error) {
    throw new ApiError(401,error?.message||"Invalid refresh Token")
   }

 })

const changeCurrentPassword  = asyncHandler(async(req,res) =>{
    const {oldPassword,newPassword} = req.body
    const user = await User.findById(req.user?._id)
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)
    if(!isPasswordCorrect){
        throw new ApiError(400,"Invalid old password")
    }
    user.password = newPassword
   await user.save({validateBeforeSave: false})
   return response.status(200).json(
    new ApiResponse(200, {},"password changed successfully")
   )
})

const getCurrentUser = asyncHandler(async (req,res)=>{
    return res
    .status(200)
    .json(
        new ApiResponse(
            200,
            req.user,"user fetched succesfully"
        )
    )
})

const updateAccountDetails = asyncHandler(async (req,res) =>{
    const {fullname,email} = req.body
    if(!(fullname || email)){
        throw new ApiError(400,"all fields are required")
    }
   const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
        $set:{
            fullname,
            email:email            
        }
    },
    {new :true}
   ).select("-password")

   return res.status(200)
   .json(new ApiResponse(200,user,"Account Details updated successfully"))
})

const updateUserAvatar = asyncHandler(async (req,res) =>{
    // steps to update avatar
    const avatarLocalPath = req.file?.path
    if(!avatarLocalPath){
        throw new ApiError(400,"avatar file is missing")
    }
   const avatar =  await uploadOnCloudinary(avatarLocalPath)
    if(!avatar.url){
        throw new ApiError(400,"Error while uploading the avatar")
    }
   const user =  await User.findByIdAndUpdate(
        req.user?._id,
        {$set:{
            avatar: avatar.url
        }},
        {new:true}
    ).select("-password")

    return res.status(200)
    .json(
         new ApiResponse(201,user,"avatar updated successfully")
    )
})

const updateUserCoverImage = asyncHandler(async (req,res) =>{
    // steps to update avatar
    const coverImageLocalPath = req.file?.path
    if(!coverImageLocalPath){
        throw new ApiError(400,"cover image file is missing")
    }
   const coverImage =  await uploadOnCloudinary(coverImageLocalPath)
    if(!coverImage.url){
        throw new ApiError(400,"Error while uploading the cover image")
    }
  const user =   await User.findByIdAndUpdate(
        req.user?._id,
        {$set:{
            coverImage: coverImage.url
        }},
        {new:true}
    ).select("-password")

    return res.status(200)
    .json(
        new ApiResponse(200,user,"coverImage updated successfully")
    )
})

export {registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,changeCurrentPassword,getCurrentUser,updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage 
}


