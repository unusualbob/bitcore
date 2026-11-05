import compression from 'compression';
import express from 'express';
import RateLimit from 'express-rate-limit';
import config from '../../config';
import { Common } from '../common';
import { logger, transports } from '../logger';
import { WalletService } from '../server';
import { LogMiddleware } from './middleware/log';

const Defaults = Common.Defaults;

export function setupAppMiddleware(app: express.Express, opts) {
  app.use(compression());

  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'x-signature,x-identity,x-identities,x-session,x-client-version,x-wallet-id,X-Requested-With,Content-Type,Authorization'
    );
    res.setHeader('x-service-version', WalletService.getServiceVersion());
    next();
  });

  app.use((req, res, next) => {
    if ('OPTIONS' == req.method) {
      res.sendStatus(200);
      res.end();
      return;
    }
    next();
  });

  app.enable('trust proxy');

  app.use((req, res, next) => {
    req.on('abort', () => {
      logger.warn('Request aborted by the client');
    });
    next();
  });

  const POST_LIMIT = 1024 * 100;
  const POST_LIMIT_LARGE = 2 * 1024 * 1024;

  app.use((req, res, next) => {
    if (req.path.includes('/txproposals') || req.path.includes('/tss/')) {
      return express.json({ limit: POST_LIMIT_LARGE })(req, res, next);
    } else {
      return express.json({ limit: POST_LIMIT })(req, res, next);
    }
  });

  // TEMP diagnostics: detect Object.prototype pollution (Mongo "cyclic dependency detected" errors)
  const PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
  const findProtoKeys = (obj, path = '', depth = 0, out: string[] = []) => {
    if (obj && typeof obj === 'object' && depth < 20) {
      for (const k of Object.keys(obj)) {
        const p = path ? `${path}.${k}` : k;
        if (PROTO_KEYS.has(k)) out.push(p);
        findProtoKeys(obj[k], p, depth + 1, out);
      }
    }
    return out;
  };
  const protoDiagReqInfo = req => ({
    ip: req.header('cf-connecting-ip') || Common.Utils.getIpFromReq(req),
    cfRay: req.header('cf-ray'),
    identity: req.header('x-identity'),
    userAgent: req.header('user-agent'),
    clientVersion: req.header('x-client-version')
  });
  let protoPollutionLogged = false;
  app.use((req, res, next) => {
    const suspicious = findProtoKeys({ body: req.body, query: req.query });
    if (suspicious.length) {
      logger.warn('PROTO-DIAG suspicious keys in %s %s: %o req: %o',
        req.method, req.originalUrl, suspicious, protoDiagReqInfo(req));
    }
    res.on('finish', () => {
      if (protoPollutionLogged) return;
      const keys = [];
      for (const k in {}) keys.push(k);
      if (keys.length) {
        protoPollutionLogged = true;
        logger.error('PROTO-DIAG Object.prototype polluted with keys %o; first seen after %s %s (body keys: %o) req: %o',
          keys, req.method, req.originalUrl, Object.keys(req.body || {}), protoDiagReqInfo(req));
      }
    });
    next();
  });

  app.use((req, res, next) => {
    if (config.maintenanceOpts.maintenanceMode === true) {
      const errorCode = 503;
      const errorMessage = 'BWS down for maintenance';
      res.status(503).send({ code: errorCode, message: errorMessage });
    } else {
      next();
    }
  });

  if (opts.disableLogs) {
    for (const transport of transports) {
      transport.level = 'error';
    }
  } else {
    app.use(LogMiddleware());
  }
}

export function createEstimateFeeLimiter(opts) {
  if (Defaults.RateLimit.estimateFee && !opts.ignoreRateLimiter) {
    logger.info(
      'Limiting estimate fee per IP: %o req/h',
      ((Defaults.RateLimit.estimateFee.max / Defaults.RateLimit.estimateFee.windowMs) * 60 * 60 * 1000).toFixed(2)
    );
    return new RateLimit(Defaults.RateLimit.estimateFee);
  }

  return (req, res, next) => {
    next();
  };
}
