import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, MoreThan } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { randomUUID, randomBytes } from 'crypto';
import * as bcrypt from 'bcrypt';
import { UsersService } from '../users/users.service';
import { MailService } from '../mail/mail.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { User } from '../users/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { EmailVerificationToken } from './entities/email-verification-token.entity';
import { PasswordResetToken } from './entities/password-reset-token.entity';

interface JwtPayload {
  sub: string;
  email: string;
  jti: string;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailService: MailService,
    @InjectRepository(RefreshToken)
    private readonly refreshTokenRepository: Repository<RefreshToken>,
    @InjectRepository(EmailVerificationToken)
    private readonly emailVerificationTokenRepository: Repository<EmailVerificationToken>,
    @InjectRepository(PasswordResetToken)
    private readonly passwordResetTokenRepository: Repository<PasswordResetToken>,
  ) {}

  async register(dto: RegisterDto): Promise<Omit<User, 'password'>> {
    const existingUser = await this.usersService.findByEmail(dto.email);

    if (existingUser) {
      throw new ConflictException('Este email já está em uso');
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(dto.password, saltRounds);

    const user = await this.usersService.createLocalUser({
      email: dto.email,
      password: hashedPassword,
      name: dto.name,
    });

    await this.createAndSendVerificationToken(user);

    const { password, ...result } = user;
    return result;
  }

  private async createAndSendVerificationToken(user: User): Promise<void> {
    const token = randomBytes(32).toString('hex');

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);

    const verificationToken = this.emailVerificationTokenRepository.create({
      token,
      userId: user.id,
      expiresAt,
    });

    await this.emailVerificationTokenRepository.save(verificationToken);

    await this.mailService.sendVerificationEmail(user.email, token);
  }

  async verifyEmail(token: string): Promise<{ message: string }> {
    const verificationToken =
      await this.emailVerificationTokenRepository.findOne({
        where: {
          token,
          expiresAt: MoreThan(new Date()),
        },
      });

    if (!verificationToken) {
      throw new NotFoundException('Token de verificação inválido ou expirado');
    }

    await this.usersService.markEmailAsVerified(verificationToken.userId);

    await this.emailVerificationTokenRepository.delete(verificationToken.id);

    return { message: 'E-mail verificado com sucesso!' };
  }

  async forgotPassword(dto: ForgotPasswordDto): Promise<{ message: string }> {
    const genericMessage = {
      message: 'Se este e-mail existir, você receberá um link de recuperação',
    };

    const user = await this.usersService.findByEmail(dto.email);

    if (!user) {
      return genericMessage;
    }

    const token = randomBytes(32).toString('hex');

    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1);

    const resetToken = this.passwordResetTokenRepository.create({
      token,
      userId: user.id,
      expiresAt,
    });

    await this.passwordResetTokenRepository.save(resetToken);

    await this.mailService.sendPasswordResetEmail(user.email, token);

    return genericMessage;
  }

  async resetPassword(dto: ResetPasswordDto): Promise<{ message: string }> {
    const resetToken = await this.passwordResetTokenRepository.findOne({
      where: {
        token: dto.token,
        expiresAt: MoreThan(new Date()),
      },
    });

    if (!resetToken) {
      throw new NotFoundException('Token de recuperação inválido ou expirado');
    }

    const hashedPassword = await bcrypt.hash(dto.newPassword, 10);

    await this.usersService.updatePassword(resetToken.userId, hashedPassword);

    await this.passwordResetTokenRepository.delete(resetToken.id);

    await this.refreshTokenRepository.update(
      { userId: resetToken.userId, revoked: false },
      { revoked: true },
    );

    return { message: 'Senha redefinida com sucesso!' };
  }

  async login(dto: LoginDto) {
    const user = await this.usersService.findByEmail(dto.email);

    if (!user || !user.password) {
      throw new UnauthorizedException('Credenciais inválidas');
    }

    const passwordMatches = await bcrypt.compare(dto.password, user.password);

    if (!passwordMatches) {
      throw new UnauthorizedException('Credenciais inválidas');
    }

    if (!user.isEmailVerified) {
      throw new UnauthorizedException('Email não verificado');
    }

    return this.generateTokens(user);
  }

  async refreshTokens(refreshToken: string) {
    let payload: JwtPayload;

    try {
      payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
      });
    } catch {
      throw new UnauthorizedException('Refresh token inválido ou expirado');
    }

    const storedToken = await this.refreshTokenRepository.findOne({
      where: {
        jti: payload.jti,
        userId: payload.sub,
        revoked: false,
        expiresAt: MoreThan(new Date()),
      },
    });

    if (!storedToken) {
      throw new UnauthorizedException('Refresh token inválido ou expirado');
    }

    const isValid = await bcrypt.compare(refreshToken, storedToken.tokenHash);

    if (!isValid) {
      throw new UnauthorizedException('Refresh token inválido ou expirado');
    }

    storedToken.revoked = true;
    await this.refreshTokenRepository.save(storedToken);

    const user = await this.usersService.findById(payload.sub);

    if (!user) {
      throw new UnauthorizedException('Usuário não encontrado');
    }

    return this.generateTokens(user);
  }

  private async generateTokens(user: User) {
    const jti = randomUUID();
    const payload = { sub: user.id, email: user.email, jti };

    const accessToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get('JWT_ACCESS_SECRET'),
      expiresIn: this.configService.get('JWT_ACCESS_EXPIRATION'),
    });

    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get('JWT_REFRESH_EXPIRATION'),
    });

    await this.storeRefreshToken(user.id, refreshToken, jti);

    return { accessToken, refreshToken };
  }

  private async storeRefreshToken(
    userId: string,
    refreshToken: string,
    jti: string,
  ) {
    const tokenHash = await bcrypt.hash(refreshToken, 10);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    const tokenEntity = this.refreshTokenRepository.create({
      userId,
      tokenHash,
      jti,
      expiresAt,
    });

    await this.refreshTokenRepository.save(tokenEntity);
  }
}