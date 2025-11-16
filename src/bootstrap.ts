// src/bootstrap.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger, RequestMethod, ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { getConnectionToken } from '@nestjs/mongoose';
import type { Connection } from 'mongoose';
import { ConfigService } from '@nestjs/config';
// import * as cookieParser from 'cookie-parser';
import helmet from 'helmet';
import * as bodyParser from 'body-parser';

export async function createNestApp() {
  const app = await NestFactory.create(AppModule);

  // Global pipes
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }));

  // Security
  app.use(helmet());

  // CORS (đổi về ENV key rõ ràng, không get bằng URL literal)
  const configSvc = app.get(ConfigService);
  const rawOrigins = (configSvc.get<string>('https://quizzysocialgallery.com') ?? '*').trim();
  let origin: boolean | string[] = true;
  if (rawOrigins !== '*') {
    origin = rawOrigins.split(',').map(s => s.trim()).filter(Boolean);
  }

  // app.use(cookieParser());
  app.enableCors({
    origin,
    credentials: true,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    allowedHeaders: 'Content-Type,Authorization',
  });

  // Body limits
  app.use(bodyParser.json({ limit: '10mb' }));
  app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));
  app.setGlobalPrefix('api', {});
  // Swagger
  const cfg = new DocumentBuilder()
    .setTitle('tath API')
    .setDescription('API docs for tath backend')
    .setVersion('1.0.0')
    .addBearerAuth()
    .build();
  const doc = SwaggerModule.createDocument(app, cfg);
  SwaggerModule.setup('api/docs', app, doc);

  // Mongo logs
  const conn = app.get<Connection>(getConnectionToken());
  conn.on('connected', () => console.log('[MongoDB][nest] connected'));
  conn.on('error', (e) => console.error('[MongoDB][nest] error:', e?.message || e));
  conn.on('disconnected', () => console.log('[MongoDB][nest] disconnected'));

  // Log request in
  const safeUri = configSvc.get<string>('MONGODB_URI')?.replace(/\/\/([^:]+):([^@]+)@/, '//<user>:<pass>@');
  console.log('[MongoDB] Using URI =', safeUri);
  app.use((req, _res, next) => {
    console.log('[HTTP IN]', req.method, req.originalUrl || req.url);
    next();
  });

  // In danh sách route (tùy nền tảng)
  function printAllRoutes(appRef: any) {
    const httpAdapter = appRef.getHttpAdapter?.();
    const type = httpAdapter?.getType?.(); // 'express' | 'fastify'
    const instance = httpAdapter?.getInstance?.();

    Logger.log(`HTTP adapter: ${type}`, 'Routes');

    if (type === 'fastify') {
      const tree = instance.printRoutes();
      console.log(tree);
      return;
    }

    if (type === 'express') {
      const server = appRef.getHttpServer();
      const router = server?._events?.request?._router;
      if (!router) {
        Logger.warn('Express router not found.', 'Routes');
        return;
      }
      const routes: string[] = [];
      router.stack.forEach((layer: any) => {
        if (layer.route && layer.route.path) {
          const path = layer.route.path;
          const methods = Object.keys(layer.route.methods).filter((m) => layer.route.methods[m]);
          methods.forEach((m) => routes.push(`${m.toUpperCase()} ${path}`));
        } else if (layer.name === 'router' && layer.handle?.stack) {
          layer.handle.stack.forEach((nested: any) => {
            if (nested.route) {
              const path = nested.route.path;
              const methods = Object.keys(nested.route.methods).filter((m) => nested.route.methods[m]);
              methods.forEach((m) => routes.push(`${m.toUpperCase()} ${path}`));
            }
          });
        }
      });
      routes.sort().forEach((r) => Logger.log(r, 'Routes'));
      return;
    }

    Logger.warn('Unknown HTTP adapter; cannot print routes.', 'Routes');
  }

  // Gọi sau khi init để vẫn in được routes
  await app.init();
  printAllRoutes(app);

  return app;
}
