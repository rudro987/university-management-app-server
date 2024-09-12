import httpStatus from "http-status";
import AppError from "../../errors/AppError";
import { User } from "../user/user.model";
import { TLoginUser } from "./auth.interface";
import jwt, { JwtPayload } from 'jsonwebtoken';
import config from "../../config";
import bcrypt from 'bcrypt';
import { createToken } from "./auth.utils";

const loginUser = async (payload: TLoginUser) => {
    //checking if the user already exists!

    const user = await User.isUserExistsByCustomId(payload?.id);
    
    if(!user){
        throw new AppError(httpStatus.NOT_FOUND, 'This user does not exist');
    }

    //checking if the user is already deleted

    const isDeleted = user?.isDeleted;
    
    if(isDeleted){
        throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted');
    }

    //checking if the user is blocked

    const userStatus = user?.status;
    
    if(userStatus === 'blocked'){
        throw new AppError(httpStatus.FORBIDDEN, 'This user Blocked!');
    }

    // checking if the password matches with the hashed password saved in db

    if(!(await User.isPasswordMatched(payload?.password, user?.password))){
        throw new AppError(httpStatus.FORBIDDEN, 'Password do not match!');
    }

    // Access granted by above validations. Send access token and refresh token

    //create token and send to the client side

    const jwtPayload = {
        userId: user?.id,
        role: user?.role
    }

    const accessToken = createToken(jwtPayload, config.jwt_access_secret as string, config.jwt_access_expires_in);

    const refreshToken = createToken(jwtPayload, config.jwt_refresh_secret as string, config.jwt_refresh_expires_in);

    return {
        accessToken,
        refreshToken,
        needsPasswordChange: user?.needsPasswordChange
    };
    
};

const changePassword = async (userData: JwtPayload, payload: { oldPassword: string, newPassword: string}) => {

    //checking if the user already exists!

    const user = await User.isUserExistsByCustomId(userData?.userId);
    
    if(!user){
        throw new AppError(httpStatus.NOT_FOUND, 'This user does not exist');
    }

    //checking if the user is already deleted

    const isDeleted = user?.isDeleted;
    
    if(isDeleted){
        throw new AppError(httpStatus.FORBIDDEN, 'This user is deleted');
    }

    //checking if the user is blocked

    const userStatus = user?.status;
    
    if(userStatus === 'blocked'){
        throw new AppError(httpStatus.FORBIDDEN, 'This user Blocked!');
    }

    // checking if the password matches with the hashed password saved in db

    if(!(await User.isPasswordMatched(payload?.oldPassword, user?.password))){
        throw new AppError(httpStatus.FORBIDDEN, 'Password do not match!');
    }

    //hash the new password

    const newHashedPassword = await bcrypt.hash(payload.newPassword, Number(config.bcrypt_salt_rounds));

    await User.findOneAndUpdate({
        id: userData.userId,
        role: userData.role
    }, {
        password: newHashedPassword,
        needsPasswordChange: false,
        passwordChangedAt: new Date()
    });

    return null
}

export const AuthServices = {
    loginUser,
    changePassword
};
