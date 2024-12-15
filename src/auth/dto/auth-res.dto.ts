import { User } from '@prisma/client';

export class AuthResDto {
  accessToken: string;
  refreshToken: string;
  id: number;
  email: string;
  name: string;

  private constructor(accessToken: string, refreshToken: string, id: number, email: string, name: string) {
    Object.assign(this, { accessToken, refreshToken, id, email, name });
  }

  static create(accessToken: string, refreshToken: string, user: User) {
    return new AuthResDto(accessToken, refreshToken, user.id, user.email, user.name);
  }
}
