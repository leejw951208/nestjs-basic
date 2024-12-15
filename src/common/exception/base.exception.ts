import { HttpException } from '@nestjs/common';
import { IErrorCodes } from './error.code';

export class BaseException extends HttpException {
  constructor(error: IErrorCodes, location: string) {
    super(
      {
        errorCode: error.errorCode,
        message: error.message,
        location: location,
      },
      error.statusCode,
    );
  }
}
