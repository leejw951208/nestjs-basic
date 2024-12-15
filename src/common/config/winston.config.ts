import { utilities, WinstonModule, WinstonModuleAsyncOptions } from 'nest-winston';
import * as winston from 'winston';
import * as winstonDaily from 'winston-daily-rotate-file';
import { ConsoleTransportOptions } from 'winston/lib/winston/transports';

const IS_PROD = process.env['NODE_ENV'] === 'prod';
const LOG_DIR = process.cwd() + `/logs`;

export const dailyOptions = (level: string) => {
  return {
    level,
    datePattern: 'YYYY-MM-DD',
    dirname: LOG_DIR + `/${level}`,
    filename: `%DATE%.log`,
    zippedArchive: true,
    maxSize: '10m',
    maxFiles: '14d',
    format: winston.format.combine(
      winston.format.timestamp(),
      utilities.format.nestLike('NestJS-Sample', {
        colors: false,
        prettyPrint: true,
        appName: true,
      }),
    ),
  };
};

const consoleOptions: ConsoleTransportOptions = {
  format: IS_PROD
    ? winston.format.simple()
    : winston.format.combine(
        winston.format.timestamp(),
        utilities.format.nestLike('NestJS-Sample', {
          colors: true,
          prettyPrint: true,
          appName: true,
        }),
      ),
};

export const winstonModuleAsyncOptions: WinstonModuleAsyncOptions = {
  useFactory: () => ({
    level: IS_PROD ? 'info' : 'debug',
    transports: [
      new winston.transports.Console(consoleOptions),
      new winstonDaily(dailyOptions('error')),
      new winstonDaily({
        ...dailyOptions('info'),
        level: 'info',
        format: winston.format.combine(
          winston.format((info) => {
            if (info.level === 'error') {
              return false;
            }
            return info;
          })(),
          winston.format.timestamp(),
          utilities.format.nestLike('NestJS-Sample', {
            colors: false,
            prettyPrint: true,
            appName: true,
          }),
        ),
      }),
    ],
  }),
};
