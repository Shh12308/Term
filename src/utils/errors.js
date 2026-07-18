export class ApiError extends Error {
  constructor(statusCode, message, code = null, details = null) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

export class NotFoundError extends ApiError {
  constructor(resource = 'Resource') {
    super(404, `${resource} not found`, 'NOT_FOUND');
  }
}

export class UnauthorizedError extends ApiError {
  constructor(message = 'Authentication required') {
    super(401, message, 'UNAUTHORIZED');
  }
}

export class ForbiddenError extends ApiError {
  constructor(message = 'Access denied') {
    super(403, message, 'FORBIDDEN');
  }
}

export class ValidationError extends ApiError {
  constructor(details) {
    super(400, 'Validation failed', 'VALIDATION_ERROR', details);
  }
}

export class InsufficientFundsError extends ApiError {
  constructor(message = 'Insufficient coins') {
    super(400, message, 'INSUFFICIENT_FUNDS');
  }
}

export class RateLimitError extends ApiError {
  constructor(message = 'Too many requests') {
    super(429, message, 'RATE_LIMITED');
  }
}

export class ServiceUnavailableError extends ApiError {
  constructor(service = 'Service') {
    super(503, `${service} unavailable`, 'SERVICE_UNAVAILABLE');
  }
}
