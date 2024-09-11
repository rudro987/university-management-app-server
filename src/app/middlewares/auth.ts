import { NextFunction, Request, Response } from 'express';
import catchAsync from '../utils/catchAsync';
import AppError from '../errors/AppError';
import httpStatus from 'http-status';
import jwt, { JwtPayload } from 'jsonwebtoken';
import config from '../config';
import { TUserRole } from '../modules/user/user.interface';

const auth = (...requiredRoles: TUserRole[]) => {
  return catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers.authorization;
    if(!token){
        throw new AppError(httpStatus.UNAUTHORIZED, 'You are not authorized');
    }

    //check if the token is valid

    const decoded = jwt.verify(token, config.jwt_access_secret as string) as JwtPayload;

    const role = (decoded).role;

        if(requiredRoles && !requiredRoles.includes(role)){
            throw new AppError(httpStatus.UNAUTHORIZED, 'You are not authorized');
        }
        
        req.user = decoded;
        next();

  });
};

export default auth;
