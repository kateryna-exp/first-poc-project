import { createServer } from 'node:http';
import { createGateway } from './src/gateway.mjs';

const port = Number.parseInt(process.env.PORT ?? '3000', 10);
const gateway = createGateway();

const server = createServer((request, response) => {
  Promise.resolve(gateway(request, response)).catch((error) => {
    // console.error(error);
    if (!response.headersSent) {
      response.statusCode = 500;
      response.setHeader('content-type', 'application/json; charset=utf-8');
      response.end(JSON.stringify({ error: 'internal_error' }));
    } else {
      response.destroy(error);
    }
  });
});

server.listen(port, '127.0.0.1', () => {
  // console.log(`Company npm gateway listening on http://127.0.0.1:${port}/npm/`);
});
