import { Controller, Get, Post, Body, Patch, Param, Delete, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/signin.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { User } from '@prisma/client';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signin')
  create(@Request() req: any) {
    return this.authService.siginin(req.user);
  }
}
