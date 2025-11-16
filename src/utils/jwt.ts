// src/auth/jwt.util.ts
import { ConfigService } from '@nestjs/config';
import { UserDocument } from '../users/schemas/user.schema';

interface TokenCookieOptions {
  expires: Date;
  maxAge: number;
  httpOnly: boolean;
  sameSite: 'lax' | 'strict' | 'none';
  secure?: boolean;
}

export function buildCookieOptions(
  config: ConfigService,
): { accessOpts: TokenCookieOptions; refreshOpts: TokenCookieOptions } {
  const accessMs = 5 * 60 * 1000;
  const refreshMs = 3 * 24 * 60 * 60 * 1000;

  const isProd = config.get('NODE_ENV') === 'production';

  const base: Omit<TokenCookieOptions, 'expires' | 'maxAge'> = {
    httpOnly: true,
    // nếu frontend khác domain backend, nên dùng 'none'
    sameSite: isProd ? 'none' : 'lax',
    secure: isProd,   // 👈 chỉ gửi qua HTTPS khi production
  };

  return {
    accessOpts: {
      ...base,
      expires: new Date(Date.now() + accessMs),
      maxAge: accessMs,
    },
    refreshOpts: {
      ...base,
      expires: new Date(Date.now() + refreshMs),
      maxAge: refreshMs,
    },
  };
}


export function sendAuthTokens(
    user: UserDocument,
    res: any,            // 👈 không import Response nữa
    config: ConfigService,
  ) {
    const accessToken = user.signAccessToken();
    const refreshToken = user.signRefreshToken();
  
    const { accessOpts, refreshOpts } = buildCookieOptions(config);
  
    res.cookie('access_token', accessToken, accessOpts);
    res.cookie('refresh_token', refreshToken, refreshOpts);
  
    return { accessToken };
  }