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
  // 5 phút & 3 ngày (chị có thể sửa theo env nếu muốn)
  const accessMs = 5 * 60 * 1000;
  const refreshMs = 3 * 24 * 60 * 60 * 1000;

  const base: Omit<TokenCookieOptions, 'expires' | 'maxAge'> = {
    httpOnly: true,
    sameSite: 'lax',
  };

  if (config.get('NODE_ENV') === 'production') {
    base.secure = true;
  }

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
  res: any, // dùng any để không phụ thuộc Express/Fastify
  config: ConfigService,
) {
  const accessToken = user.signAccessToken();
  const refreshToken = user.signRefreshToken();

  const { accessOpts, refreshOpts } = buildCookieOptions(config);

  res.cookie('access_token', accessToken, accessOpts);
  res.cookie('refresh_token', refreshToken, refreshOpts);

  return { accessToken, refreshToken };
}
