import config from 'config';
import { CookieOptions } from 'express';
import { User } from '../models/user.model';
import { signJwt } from './jwt';
import redisClient from './connectRedis';

// Cookie Options
const accessTokenExpiresIn = config.get<number>('accessTokenExpiresIn');
const refreshTokenExpiresIn = config.get<number>('refreshTokenExpiresIn');

const cookieOptions: CookieOptions = {
  httpOnly: true,
  sameSite: 'none',
  secure: true,
};

const accessTokenCookieOptions = {
  ...cookieOptions,
  maxAge: accessTokenExpiresIn * 60 * 1000,
  expires: new Date(Date.now() + accessTokenExpiresIn * 60 * 1000),
};

const refreshTokenCookieOptions = {
  ...cookieOptions,
  maxAge: refreshTokenExpiresIn * 60 * 1000,
  expires: new Date(Date.now() + refreshTokenExpiresIn * 60 * 1000),
};

// Sign JWT Tokens
function signTokens(user: User) {
  const userId: string = user._id.toString();
  const access_token = signJwt({ userId }, 'accessTokenPrivateKey', {
    expiresIn: `${accessTokenExpiresIn}m`,
  });

  const refresh_token = signJwt({ userId }, 'refreshTokenPrivateKey', {
    expiresIn: `${refreshTokenExpiresIn}m`,
  });

  redisClient.set(userId, JSON.stringify(user), {
    EX: refreshTokenExpiresIn * 60,
  });

  return { access_token, refresh_token };
}

export { accessTokenCookieOptions, refreshTokenCookieOptions, signTokens };
