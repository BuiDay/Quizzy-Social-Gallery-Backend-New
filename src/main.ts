import { createNestApp } from './bootstrap';
async function bootstrap() {
  const app = await createNestApp();

  const port = process.env.PORT ? Number(process.env.PORT) : 4000;
  await app.listen(port);
  console.log(`[Nest] HTTP server started on http://localhost:${port}`);
  console.log(`Swagger docs: http://localhost:${port}/docs`);
}

bootstrap();