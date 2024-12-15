export interface IErrorCodes {
  errorCode: string;
  statusCode: number;
  message: string;
}

export const NOT_FOUND: {
  [key: string]: IErrorCodes;
} = {
  GENERAL: {
    errorCode: 'NOT_FOUND_001',
    statusCode: 404,
    message: 'Not found',
  },
  USER_NOT_FOUND: {
    errorCode: 'NOT_FOUND_002',
    statusCode: 404,
    message: 'User not found',
  },
};

export const UNAUTHORIZED: {
  [key: string]: IErrorCodes;
} = {
  GENERAL: {
    errorCode: 'UNAUTHORIZED_001',
    statusCode: 401,
    message: 'Unauthorized',
  },
  PASSWORD_NOT_MATCHED: {
    errorCode: 'UNAUTHORIZED_002',
    statusCode: 401,
    message: 'Password not matched',
  },
};

export const FORBIDDEN: {
  [key: string]: IErrorCodes;
} = {
  GENERAL: {
    errorCode: 'FORBIDDEN_001',
    statusCode: 403,
    message: 'Forbidden',
  },
  USER_NOT_FOUND: {
    errorCode: 'FORBIDDEN_002',
    statusCode: 403,
    message: 'Forbidden',
  },
};

export const BAD_REQUEST: {
  [key: string]: IErrorCodes;
} = {
  GENERAL: {
    errorCode: 'BAD_REQUEST_001',
    statusCode: 400,
    message: 'Bad request',
  },
  USER_NOT_FOUND: {
    errorCode: 'BAD_REQUEST_002',
    statusCode: 400,
    message: 'Bad request',
  },
};

export const INTERNAL_SERVER_ERROR: {
  [key: string]: IErrorCodes;
} = {
  GENERAL: {
    errorCode: 'INTERNAL_SERVER_ERROR_001',
    statusCode: 500,
    message: 'Internal server error',
  },
};
