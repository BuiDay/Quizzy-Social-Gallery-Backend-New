import { IsEmail, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RegisterUserDto {
  @ApiProperty({ example: 'Quynh Nguyen', description: 'Tên người dùng' })
  @IsString()
  name: string;

  @ApiProperty({
    example: 'user@example.com',
    description: 'Email đăng ký',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: '123456',
    description: 'Mật khẩu (ít nhất 6 ký tự)',
  })
  @IsString()
  @MinLength(6)
  password: string;
}
