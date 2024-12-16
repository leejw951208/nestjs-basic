import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import * as bcryptjs from 'bcryptjs';
import { User } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { AuthResDto } from './dto/auth-res.dto';
import { SignupReqDto } from './dto/signup-req.dto';
import { UserEntity } from '../user/entities/user.entity';
import { BaseException } from '../common/exception/base.exception';
import { NOT_FOUND, UNAUTHORIZED } from '../common/exception/error.code';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import { Inject } from '@nestjs/common';
import { Logger as WinstonLogger } from 'winston';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
    @Inject(WINSTON_MODULE_NEST_PROVIDER) private readonly logger: WinstonLogger,
  ) {}

  async validateUser(email: string, password: string): Promise<User> {
    const user = await this.prisma.user.findFirst({ where: { email } });
    if (!user) {
      throw new BaseException(NOT_FOUND.USER_NOT_FOUND, this.constructor.name);
    }
    const isMatched = await bcryptjs.compare(password, user.password);
    if (!isMatched) {
      throw new BaseException(UNAUTHORIZED.PASSWORD_NOT_MATCHED, this.constructor.name);
    }
    return user;
  }

  async siginin(user: User, loginInfo: { ip: string; userAgent: string }): Promise<AuthResDto> {
    // Save login history
    await this.prisma.loginHistory.create({
      data: {
        userId: user.id,
        ip: loginInfo.ip,
        userAgent: loginInfo.userAgent,
      },
    });
    this.logger.info(`Login history recorded for user ${user.id}`, {
      userId: user.id,
      ip: loginInfo.ip,
      userAgent: loginInfo.userAgent,
      context: this.constructor.name,
    });

    const accessToken = await this.createAccessToken(user);
    const refreshToken = await this.createRefreshToken(user);

    return AuthResDto.create(accessToken, refreshToken, user);
  }

  async signup(reqDto: SignupReqDto): Promise<string> {
    const hashedPassword = await bcryptjs.hash(reqDto.password, 10);
    const userEntity = UserEntity.create(Object.assign(reqDto, { password: hashedPassword }));
    await this.prisma.user.create({ data: userEntity });
    return 'succeed!';
  }

  private async createAccessToken(user: User): Promise<string> {
    const payload = {
      id: user.id,
      email: user.email,
      name: user.name,
      type: 'ac',
    };

    return await this.jwtService.signAsync(payload, {
      secret: this.configService.get<string>('JWT_SECRET_KEY'),
      expiresIn: this.configService.get<string>('JWT_ACCESS_EXPIRES_IN'),
    });
  }

  private async createRefreshToken(user: User): Promise<string> {
    const payload = {
      id: user.id,
      type: 're',
    };

    return await this.jwtService.signAsync(payload, {
      secret: this.configService.get<string>('JWT_SECRET_KEY'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRES_IN'),
    });
  }
}
