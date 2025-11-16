import {
    Body,
    Controller,
    Get,
    Post,
    Put,
    Req,
    Res,
    UseGuards,
  } from '@nestjs/common';
  import { UsersService } from './users.service';
  import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
  
  @Controller('users')
  export class UsersController {
    constructor(private readonly usersService: UsersService) {}
    
    @Post('active-user')
    async activateUser(@Body() body: any) {
      return this.usersService.activateUser(body);
    }
  
    // POST /api/users/login-user
    @Post('registration')
    async register(@Body() body: RegisterUserDto) {
      return this.usersService.register(body);
    }
  
    @Post('login-user')
    async login(
      @Body() body: LoginUserDto,                 // 👈 dùng DTO ở đây
      @Res({ passthrough: true }) res: any,
    ) {
      return this.usersService.login(body, res);
    }
  
    // GET /api/users/logout-user
    @UseGuards(JwtAuthGuard)
    @Get('logout-user')
    async logout(@Res({ passthrough: true }) res: any) {
      return this.usersService.logout(res);
    }
  
    // GET /api/users/refresh-token
    @Get('refresh-token')
    async refresh(
      @Req() req: any,
      @Res({ passthrough: true }) res: any,
    ) {
      const refreshToken = req.cookies?.['refresh_token'];
      return this.usersService.updateAccessToken(refreshToken, res);
    }
  
    // GET /api/users/get-user-by-id
    @UseGuards(JwtAuthGuard)
    @Get('get-user-by-id')
    async getMe(@Req() req: any) {
      const userId = req.user._id.toString();
      return this.usersService.getMe(userId);
    }
  
    // PUT /api/users/update-user-info
    @UseGuards(JwtAuthGuard)
    @Put('update-user-info')
    async updateUserInfo(@Req() req: any, @Body() body: any) {
      const userId = req.user._id.toString();
      return this.usersService.updateUserInfo(userId, body);
    }
  
    // PUT /api/users/update-user-password
    @UseGuards(JwtAuthGuard)
    @Put('update-user-password')
    async updatePassword(@Req() req: any, @Body() body: any) {
      const userId = req.user._id.toString();
      return this.usersService.updatePassword(userId, body);
    }
  
    // PUT /api/users/update-user-avatar
    @UseGuards(JwtAuthGuard)
    @Put('update-user-avatar')
    async updateAvatar(@Req() req: any, @Body('avatar') avatar: string) {
      const userId = req.user._id.toString();
      return this.usersService.updateAvatar(userId, avatar);
    }
  
    // GET /api/users/get-collections
    @UseGuards(JwtAuthGuard)
    @Get('get-collections')
    async getCollections(@Req() req: any) {
      const userId = req.user._id.toString();
      return this.usersService.getCollections(userId);
    }
  
    // POST /api/users/forgot-password
    @Post('forgot-password')
    async forgotPassword(@Body() body: any) {
      return this.usersService.forgotPassword(body);
    }
  
    // POST /api/users/reset-password
    @Post('reset-password')
    async resetPassword(@Body() body: any) {
      return this.usersService.resetPassword(body);
    }
  }
  