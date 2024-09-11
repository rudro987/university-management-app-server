import httpStatus from "http-status";
import catchAsync from "../../utils/catchAsync";
import { AuthServices } from "./auth.service";

const loginUser = catchAsync(async (req, res) => {
  const result = await AuthServices.loginUser(req.body);

  res.status(httpStatus.OK).json({
    success: true,
    message: 'User is logged in successfully!',
    data: result,
  });
});

export const AuthControllers = {
    loginUser
};