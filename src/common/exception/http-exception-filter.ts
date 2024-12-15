import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus } from '@nestjs/common';
import { Response } from 'express';
import { Logger } from 'winston';
import { Inject } from '@nestjs/common';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import { BaseException } from './base.exception';
import { IErrorCodes, INTERNAL_SERVER_ERROR } from './error.code';

// @Catch(HttpException, BaseException)
export class HttpExceptionFilter implements ExceptionFilter {
  constructor(@Inject(WINSTON_MODULE_NEST_PROVIDER) private readonly logger: Logger) {}

  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest();

    if (exception instanceof BaseException) {
      const status = exception.getStatus();
      const errorResponse = exception.getResponse() as IErrorCodes;
      const message = errorResponse.message;
      // 로그 출력
      this.logger.error(`HTTP Exception: ${message}`, {
        statusCode: status,
        errorCode: errorResponse.errorCode,
        message: message,
        timestamp: new Date().toISOString(),
        path: request.url,
      });
      // 클라이언트에 응답
      response.status(status).json({
        statusCode: status,
        errorCode: errorResponse.errorCode,
        message: message,
        timestamp: new Date().toISOString(),
        path: request.url,
      });
    } else {
      const status = HttpStatus.INTERNAL_SERVER_ERROR;
      const message = exception.message || 'Internal server error';
      const json = {
        ...INTERNAL_SERVER_ERROR.GENERAL,
        timestamp: new Date().toISOString(),
        path: request.url,
      };
      // 로그 출력
      this.logger.error(`HTTP Exception: ${message}`, json);
      // 클라이언트에 응답
      response.status(status).json(json);
    }
  }
}
