import { IsEmail, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LoginUserDto {
  @ApiProperty({
    example: 'user@example.com',
    description: 'Email đăng nhập',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: '123456',
    description: 'Mật khẩu',
  })
  @IsString()
  @MinLength(6)
  password: string;
}
