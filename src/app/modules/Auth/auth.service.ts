import httpStatus from "http-status";
import AppError from "../../errors/AppError";
import { User } from "../user/user.model";
import { TLoginUser } from "./auth.interface";
import jwt from 'jsonwebtoken';
import config from "../../config";

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
        userId: user,
        role: user?.role
    }

    const accessToken = jwt.sign(jwtPayload, config.jwt_access_secret as string, { expiresIn: '10d' });


    return {
        accessToken,
        needsPasswordChange: user.needsPasswordChange
    };
    
};


export const AuthServices = {
    loginUser
};
