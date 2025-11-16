import {
    Injectable,
    CanActivate,
    ExecutionContext,
    UnauthorizedException,
  } from '@nestjs/common';
  import * as jwt from 'jsonwebtoken';
  import { InjectModel } from '@nestjs/mongoose';
  import { User, UserDocument } from '../users/schemas/user.schema';
  import { Model } from 'mongoose';
  import { ConfigService } from '@nestjs/config';
  
  @Injectable()
  export class JwtAuthGuard implements CanActivate {
    constructor(
      @InjectModel(User.name) private userModel: Model<UserDocument>,
      private config: ConfigService,
    ) {}
  
    async canActivate(context: ExecutionContext): Promise<boolean> {
      const http = context.switchToHttp();
      const req: any = http.getRequest();
  
      const tokenFromCookie = req.cookies?.['access_token'];
      const tokenFromHeader = req.headers?.authorization?.split(' ')[1];
      const token = tokenFromCookie || tokenFromHeader;
  
      if (!token) {
        throw new UnauthorizedException('Không có token');
      }
  
      const secret = this.config.get<string>('ACCESS_TOKEN');
      if (!secret) throw new Error('ACCESS_TOKEN not defined');
  
      try {
        const decoded = jwt.verify(token, secret) as { id: string };
        const user = await this.userModel.findById(decoded.id);
  
        if (!user) {
          throw new UnauthorizedException('User not found');
        }
  
        req.user = user;
        return true;
      } catch {
        throw new UnauthorizedException('Token không hợp lệ');
      }
    }
  }
  