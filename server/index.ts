import express, { Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';
import { getDatabase } from './db';
import { sessionMiddleware } from './middleware';
import { authRouter } from './routes/auth';
import { documentsRouter } from './routes/documents';
import { sharingRouter } from './routes/sharing';

dotenv.config();

export function createApp(): express.Express {
  const app = express();

  // Initialize DB schema
  getDatabase();

  // Basic security headers
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    // HSTS for production (1 year including subdomains)
    if (process.env.NODE_ENV === 'production') {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
  });

  // Body parser with 50MB limit for client-encrypted document payload blobs
  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ extended: true, limit: '50mb' }));
  app.use(cookieParser());

  // Session & Auth middleware
  app.use(sessionMiddleware);

  // Mount API routers
  app.use('/api/auth', authRouter);
  app.use('/api/documents', documentsRouter);
  app.use('/api/sharing', sharingRouter);

  // Health check
  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({ status: 'ok', service: 'SecureBox Backend' });
  });

  // Serve static files in production
  if (process.env.NODE_ENV === 'production') {
    const distPath = path.resolve(__dirname, '../dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  return app;
}

if (process.env.NODE_ENV !== 'test') {
  const port = process.env.PORT || 3001;
  const app = createApp();
  app.listen(port, () => {
    console.log('[SecureBox] Server running on port ' + port + '');
  });
}