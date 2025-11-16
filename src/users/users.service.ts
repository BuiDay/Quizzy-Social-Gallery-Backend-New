import {
    Injectable,
    BadRequestException,
    UnauthorizedException,
    NotFoundException,
  } from '@nestjs/common';
  import { InjectModel } from '@nestjs/mongoose';
  import { User, UserDocument } from './schemas/user.schema';
  import { Model } from 'mongoose';
  import * as jwt from 'jsonwebtoken';
  import * as crypto from 'crypto';
  import { ConfigService } from '@nestjs/config';
  import { sendAuthTokens } from '../auth/jwt.util';
  import * as cloudinary from 'cloudinary';
  
  // nếu muốn có DTO riêng thì sau này mình thêm class, hiện tại dùng any cho nhanh
  
  @Injectable()
  export class UsersService {
    constructor(
      @InjectModel(User.name) private userModel: Model<UserDocument>,
      private config: ConfigService,
    ) {}
  
    // ========== REGISTER ==========
    async register(body: any) {
      const { name, email, password } = body;
  
      const isEmailExist = await this.userModel.findOne({ email });
      if (isEmailExist) {
        throw new BadRequestException('Email already exist');
      }
  
      await this.userModel.create({ name, email, password });
  
      return { success: true };
    }
  
    // ========== CREATE ACTIVATION TOKEN ==========
    createActivationToken(user: any) {
      const activationCode = Math.floor(1000 + Math.random() * 9000).toString();
      const secret = this.config.get<string>('ACTIVATION_SECRET') || '';
  
      const token = jwt.sign({ user, activationCode }, secret, {
        expiresIn: '5m',
      });
  
      return { token, activationCode };
    }
  
    // ========== ACTIVATE USER ==========
    async activateUser(body: any) {
      const { activation_token, activation_code } = body;
      const secret = this.config.get<string>('ACTIVATION_SECRET') || '';
  
      let decoded: { user: any; activationCode: string };
      try {
        decoded = jwt.verify(activation_token, secret) as any;
      } catch {
        throw new BadRequestException('Token active không hợp lệ hoặc đã hết hạn');
      }
  
      if (decoded.activationCode !== String(activation_code)) {
        throw new BadRequestException('Invalid activation code');
      }
  
      const { email } = decoded.user;
      const existUser = await this.userModel.findOne({ email });
      if (existUser) {
        throw new BadRequestException('Email already exist');
      }
  
      await this.userModel.create(decoded.user);
  
      return { success: true };
    }
  
    // ========== LOGIN ==========
    async login(body: any, res: any) {
        const { email, password } = body;
        if (!email || !password) {
          throw new BadRequestException('Vui lòng nhập email và mật khẩu');
        }
      
        const userWithPassword = await this.userModel
          .findOne({ email })
          .select('+password');
      
        if (!userWithPassword) {
          throw new BadRequestException('Không tìm thấy tài khoản!');
        }
      
        const isPasswordMatch = await userWithPassword.comparePassword(password);
        if (!isPasswordMatch) {
          throw new BadRequestException('Mật khẩu không đúng!');
        }
      
        // ✅ thêm check null ở đây
        const user = await this.userModel.findById(userWithPassword._id);
        if (!user) {
          throw new UnauthorizedException('User not found');
        }
      
        const { accessToken } = sendAuthTokens(user, res, this.config);
      
        return {
          success: true,
          user,
          accessToken,
        };
      }
    // ========== LOGOUT ==========
    async logout(res: any) {
      res.cookie('access_token', '', { maxAge: 1 });
      res.cookie('refresh_token', '', { maxAge: 1 });
  
      return {
        success: true,
        message: 'Logout successfully',
      };
    }
  
    // ========== REFRESH TOKEN ==========
    async updateAccessToken(refreshToken: string, res: any) {
        const secret = this.config.get<string>('REFRESH_TOKEN');
        if (!refreshToken || !secret) {
          throw new UnauthorizedException('Could not refresh token');
        }
      
        let decoded: jwt.JwtPayload;
        try {
          decoded = jwt.verify(refreshToken, secret) as jwt.JwtPayload;
        } catch {
          throw new UnauthorizedException('Could not refresh token');
        }
      
        const session = await this.userModel.findById(decoded.id);
      
        // ✅ check null trước
        if (!session) {
          throw new UnauthorizedException('Could not refresh token');
        }
      
        const user = session; // giờ TS biết chắc user != null
        const { accessToken } = sendAuthTokens(user, res, this.config);
      
        return { success: true, accessToken };
      }
  
    // ========== GET CURRENT USER ==========
    async getMe(userId: string) {
      const user = await this.userModel.findById(userId);
      if (!user) throw new NotFoundException('User not found');
      return { success: true, user };
    }
  
    // ========== UPDATE USER INFO ==========
    async updateUserInfo(userId: string, body: any) {
      const user = await this.userModel.findById(userId);
      if (!user) throw new NotFoundException('User not found');
  
      if (body.name) {
        user.name = body.name;
      }
  
      await user.save();
      return { success: true, user };
    }
  
    // ========== UPDATE PASSWORD ==========
    async updatePassword(userId: string, body: any) {
      const { oldPassword, newPassword } = body;
  
      const user = await this.userModel
        .findById(userId)
        .select('+password');
  
      if (!user || !user.password) {
        throw new BadRequestException('Invalid user');
      }
  
      const isPasswordMatch = await user.comparePassword(oldPassword);
  
      if (!isPasswordMatch) {
        throw new BadRequestException('Invalid old password');
      }
  
      user.password = newPassword;
      await user.save();
  
      return { success: true };
    }
  
    // ========== UPDATE AVATAR ==========
    async updateAvatar(userId: string, avatar: string) {
      const user = await this.userModel.findById(userId);
      if (!user) throw new NotFoundException('User not found');
  
      if (!avatar) {
        throw new BadRequestException('Avatar is required');
      }
  
      if (user.avatar?.public_id) {
        await cloudinary.v2.uploader.destroy(user.avatar.public_id);
      }
  
      const myCloud = await cloudinary.v2.uploader.upload(avatar, {
        folder: 'avatars',
        width: 150,
      });
  
      user.avatar = {
        public_id: myCloud.public_id,
        url: myCloud.secure_url,
      };
  
      await user.save();
      return { success: true, user };
    }
  
    // ========== FORGOT PASSWORD ==========
    async forgotPassword(body: any) {
      const { email } = body;
  
      const user = await this.userModel.findOne({ email });
      if (!user) {
        throw new BadRequestException('Không tìm thấy Email!');
      }
  
      const token = crypto.randomBytes(32).toString('hex');
      user.passwordResetToken = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');
      user.passwordResetExpires = Date.now() + 30 * 60 * 1000;
  
      await user.save();
  
      const origin =
        this.config.get<string>('FRONTEND_URL') ||
        this.config.get<string>('ORIGIN') ||
        '';
      const resetURL = `${origin}/reset-password?token=${token}`;
      const data = { resetURL, name: user.name };
  
      // chị thay bằng hàm sendMail thực tế của project (em giả định đã có)
      // await sendMail({
      //   email: user.email,
      //   subject: 'Quên mật khẩu',
      //   template: 'forgot-password.ejs',
      //   data,
      // });
  
      return {
        success: true,
        message: `Vui lòng kiểm tra: ${email} để thay đổi password`,
        token,
        resetURL,
        data,
      };
    }
  
    // ========== RESET PASSWORD ==========
    async resetPassword(body: any) {
      const { token, password } = body;
  
      const hashToken = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');
  
      const user = await this.userModel.findOne({
        passwordResetToken: hashToken,
        passwordResetExpires: { $gt: Date.now() },
      });
  
      if (!user) {
        throw new BadRequestException('Đã hết hạn, vui lòng thử lại!');
      }
  
      user.password = password;
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      user.passwordChangedAt = Date.now();
  
      await user.save();
      return { success: true };
    }
  
    // ========== GET COLLECTIONS ==========
    async getCollections(userId: string) {
      const user = await this.userModel
        .findById(userId)
        .populate({
          path: 'products',
          select: ['-reviews', '-price', '-description', '-createdAt', '-updatedAt'],
        });
  
      if (!user) {
        throw new BadRequestException('Đã hết hạn, vui lòng thử lại!');
      }
  
      return {
        success: true,
        products: user.products,
      };
    }
  }
  