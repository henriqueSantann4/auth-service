import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;

  constructor(private readonly configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.configService.get('MAIL_HOST'),
      port: this.configService.get('MAIL_PORT'),
      auth: {
        user: this.configService.get('MAIL_USER'),
        pass: this.configService.get('MAIL_PASSWORD'),
      },
    });
  }

  async sendVerificationEmail(to: string, token: string): Promise<void> {
    const appUrl = this.configService.get('APP_URL');
    const verificationUrl = `${appUrl}/auth/verify-email?token=${token}`;

    await this.transporter.sendMail({
      from: this.configService.get('MAIL_FROM'),
      to,
      subject: 'Confirme seu e-mail',
      html: `
        <h2>Bem-vindo!</h2>
        <p>Clique no link abaixo para confirmar seu e-mail:</p>
        <a href="${verificationUrl}">${verificationUrl}</a>
        <p>Este link expira em 24 horas.</p>
      `,
    });
  }
}