import { PartialType } from '@nestjs/mapped-types';
import { CreateAuthDto } from './signin.dto';

export class UpdateAuthDto extends PartialType(CreateAuthDto) {}
