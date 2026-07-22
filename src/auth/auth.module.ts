import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { MailModule } from '../mail/mail.module';
import { RefreshToken } from './entities/refresh-token.entity';
import { EmailVerificationToken } from './entities/email-verification-token.entity';
import { PasswordResetToken } from './entities/password-reset-token.entity';
import { JwtStrategy } from './strategies/jwt.strategy';

@Module({
  imports: [
    UsersModule,
    PassportModule,
    MailModule,
    JwtModule.register({}),
    TypeOrmModule.forFeature([
      RefreshToken,
      EmailVerificationToken,
      PasswordResetToken,
    ]),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
})
export class AuthModule {}