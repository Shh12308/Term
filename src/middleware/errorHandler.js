import { ApiError } from '../utils/errors.js';
import logger from '../utils/logger.js';
import { env } from '../config/index.js';

/**
 * Global error handler middleware
 */
export function errorHandler(err, req, res, next) {
  // Log the error
  const errorInfo = {
    err,
    event: 'request_error',
    method: req.method,
    path: req.path,
    requestId: req.id,
    userId: req.user?.id,
  };

  if (err instanceof ApiError) {
    // Operational error - log at appropriate level
    if (err.statusCode >= 500) {
      logger.error(errorInfo, err.message);
    } else {
      logger.warn(errorInfo, err.message);
    }
    
    return res.status(err.statusCode).json({
      error: err.message,
      code: err.code,
      details: env.NODE_ENV === 'development' ? err.details : undefined,
    });
  }

  if (err instanceof z.ZodError) {
    logger.warn({ ...errorInfo, issues: err.issues }, 'Validation error');
    return res.status(400).json({
      error: 'Validation failed',
      code: 'VALIDATION_ERROR',
      details: err.issues.map(issue => ({
        field: issue.path.join('.'),
        message: issue.message,
      })),
    });
  }

  // Unexpected error
  logger.error(errorInfo, 'Unexpected error');
  
  res.status(500).json({
    error: env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message,
    code: 'INTERNAL_ERROR',
  });
}

/**
 * 404 handler
 */
export function notFoundHandler(req, res) {
  res.status(404).json({
    error: 'Not found',
    code: 'NOT_FOUND',
    path: req.path,
  });
}

// Import zod for ZodError check
import z from 'zod';
