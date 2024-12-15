import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../../user/user.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService, // 사용자 정보를 조회하기 위한 서비스
  ) {
    super({
      // JWT 토큰 추출 방법 설정
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      // 토큰 만료 무시 여부
      ignoreExpiration: false,
      // JWT 시크릿 키 설정
      secretOrKey: configService.get<string>('JWT_SECRET_KEY'),
    });
  }

  // JWT 토큰 검증 후 실행되는 메소드
  async validate(payload: any) {
    try {
      // payload에서 사용자 ID 추출
      const { sub: userId } = payload;

      // 데이터베이스에서 사용자 정보 조회
      const user = await this.userService.findById(userId);

      if (!user) {
        throw new UnauthorizedException('사용자를 찾을 수 없습니다.');
      }

      // 사용자 상태 확인 (예: 계정 활성화 여부)
      if (!user.isActive) {
        throw new UnauthorizedException('비활성화된 계정입니다.');
      }

      // request.user에 담길 정보
      return {
        id: user.id,
        email: user.email,
      };
    } catch (error) {
      throw new UnauthorizedException('인증에 실패했습니다.');
    }
  }
}
