import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../../prisma/prisma.service';
import * as bcryptjs from 'bcryptjs';
import { User } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async validateUser(email: string, password: string): Promise<User> {
    const user = await this.prisma.user.findFirst({ where: { email } });
    if (!user) {
      return null;
    }
    const isMatched = await bcryptjs.compare(password, user.password);
    if (!isMatched) {
      return null;
    }
    return user;
  }

  async siginin(user: User) {
    // 로그인 이력 저장

    await this.createAccessToken(user);
  }

  private async createAccessToken(user: User): Promise<string> {
    const payload = {
      id: user.id,
      email: user.email,
      name: user.name,
    };

    return await this.jwtService.signAsync(payload, {
      secret: this.configService.get<string>('JWT_SECRET'),
      expiresIn: this.configService.get<number>('JWT_EXPIRES_IN'),
    });
  }
}
