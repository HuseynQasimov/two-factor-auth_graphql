import {
  AuthenticationError,
  ForbiddenError,
  ValidationError,
} from 'apollo-server-core';
import bcrypt from 'bcryptjs';
import config from 'config';
import speakeasy from 'speakeasy';
import errorHandler from '../controllers/error.controller';
import deserializeUser from '../middlewares/deserializeUser';
import UserModel, { User } from '../models/user.model';
import { ChangePasswordInput, LoginInput } from '../schemas/user.schema';
import { Context } from '../types/context';
import redisClient from '../utils/connectRedis';
import { signJwt, verifyJwt } from '../utils/jwt';
import {
  accessTokenCookieOptions,
  refreshTokenCookieOptions,
  signTokens,
} from '../utils/signTokens';
import { generateOTP } from '../utils/two-factor-auth';

export default class UserService {
  async comparePasswords(hashedPassword: string, candidatePassword: string) {
    return await bcrypt.compare(candidatePassword, hashedPassword);
  }

  async findByEmail(email: string) {
    return UserModel.findOne({ email }).select('+password');
  }

  // Register User
  async signUpUser(input: Partial<User>) {
    try {
      const { qrCode, secretKey } = await generateOTP();

      // Create new user
      const user = await UserModel.create({
        email: input.email,
        password: input.password,
        passwordConfirm: input.passwordConfirm,
        otpSecretKey: secretKey.base32,
        qrCode,
      });

      return {
        status: 'success',
        user,
      };
    } catch (error: any) {
      if (error.code === 11000) {
        return new ValidationError('Email already exists');
      }
      errorHandler(error);
    }
  }

  // Login User
  async loginUser(input: LoginInput, { res }: Context) {
    try {
      const message = 'Invalid email or password';

      // Find user by email
      const user = await this.findByEmail(input.email);

      if (!user) {
        return new AuthenticationError(message);
      }

      // Compare passwords
      const passIsValid = await this.comparePasswords(
        user.password,
        input.password
      );

      // Verify OTP
      const otpIsValid = speakeasy.totp.verify({
        secret: user.otpSecretKey,
        encoding: 'base32',
        token: input.otp,
      });

      if (!passIsValid || !otpIsValid) {
        return new AuthenticationError(message);
      }

      // Sign JWT Tokens
      const { access_token, refresh_token } = signTokens(user);

      // Add Tokens to Context
      res.cookie('access_token', access_token, accessTokenCookieOptions);
      res.cookie('refresh_token', refresh_token, refreshTokenCookieOptions);
      res.cookie('logged_in', 'true', {
        ...accessTokenCookieOptions,
        httpOnly: false,
      });

      return {
        status: 'success',
        access_token,
      };
    } catch (error: any) {
      errorHandler(error);
    }
  }

  // Get Currently Logged In User
  async getMe({ req, res, deserializeUser }: Context) {
    try {
      const user = await deserializeUser(req);
      return {
        status: 'success',
        user,
      };
    } catch (error: any) {
      errorHandler(error);
    }
  }

  // Refresh Access Token
  async refreshAccessToken({ req, res }: Context) {
    try {
      // Get the refresh token
      const { refresh_token } = req.cookies;

      // Validate the RefreshToken
      const decoded = verifyJwt<{ userId: string }>(
        refresh_token,
        'refreshTokenPrivateKey'
      );

      if (!decoded) {
        throw new ForbiddenError('Could not refresh access token');
      }

      // Check if user's session is valid
      const session = await redisClient.get(decoded.userId);

      if (!session) {
        throw new ForbiddenError('User session has expired');
      }

      // Check if user exist and is verified
      const user = await UserModel.findById(JSON.parse(session)._id);

      if (!user) {
        throw new ForbiddenError('Could not refresh access token');
      }

      // Sign new access token
      const accessTokenExpiresIn = config.get<number>('accessTokenExpiresIn');
      const access_token = signJwt(
        { userId: user._id },
        'accessTokenPrivateKey',
        {
          expiresIn: `${accessTokenExpiresIn}m`,
        }
      );

      // Send access token cookie
      res.cookie('access_token', access_token, accessTokenCookieOptions);
      res.cookie('logged_in', 'true', {
        ...accessTokenCookieOptions,
        httpOnly: false,
      });

      return {
        status: 'success',
        access_token,
      };
    } catch (error) {
      errorHandler(error);
    }
  }

  // Logout User
  async logoutUser({ req, res }: Context) {
    try {
      const user = await deserializeUser(req);

      // Delete the user's session
      await redisClient.del(String(user?._id));

      // Logout user
      res.cookie('access_token', '', { maxAge: -1 });
      res.cookie('refresh_token', '', { maxAge: -1 });
      res.cookie('logged_in', '', { maxAge: -1 });

      return true;
    } catch (error) {
      errorHandler(error);
    }
  }

  // Change user's password
  async changePassword(
    input: ChangePasswordInput,
    { req, res, deserializeUser }: Context
  ) {
    try {
      // Get user's data
      const user = await deserializeUser(req);

      if (!user) {
        throw new ForbiddenError('User is not found');
      }

      // Validate user's old password
      const passIsValid = this.comparePasswords(
        user.password,
        input.oldPassword
      );

      if (!passIsValid) {
        throw new ForbiddenError('Invalid password');
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(
        input.newPassword,
        config.get<number>('costFactor')
      );

      await UserModel.updateOne(
        { email: user.email },
        { password: hashedPassword }
      );

      return {
        status: 'success',
        user,
      };
    } catch (error: any) {
      errorHandler(error);
    }
  }
}
