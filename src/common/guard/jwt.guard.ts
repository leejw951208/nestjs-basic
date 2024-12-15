import { ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Observable } from 'rxjs';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorator/public.decorator';

@Injectable()
export class JwtGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
    // @Public() 데코레이터가 있는지 확인
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // Public 라우트인 경우 인증 검사 건너뛰기
    if (isPublic) {
      return true;
    }

    // JWT Strategy로 토큰 검증을 위임
    return super.canActivate(context);
  }

  handleRequest(err: any, user: any, info: any) {
    console.log(err, user, info);
    if (err || !user) {
      throw err || new UnauthorizedException('유효하지 않은 토큰입니다.');
    }
    return user;
  }
}
