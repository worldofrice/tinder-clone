import fastify, { FastifyReply, FastifyRequest } from 'fastify';
import fastifySession from '@fastify/session';
import fastifyJWT from '@fastify/jwt';
import dotenv from 'dotenv';
import webauthnRoutes from './routes/webauthn'; // Import the webauthn routes
import path from 'path';
import fastifyStatic from '@fastify/static';

dotenv.config();

const server = fastify();

// Add this helper method to your Fastify instance
declare module 'fastify' {
    interface FastifyInstance {
        authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    }
}

server.register(require('@fastify/cookie'), {
    secret: "my-secret", // for cookies signature
    hook: 'onRequest', // set to false to disable cookie autoparsing or set autoparsing on any of the following hooks: 'onRequest', 'preParsing', 'preHandler', 'preValidation'. default: 'onRequest'
    parseOptions: {}  // options for parsing cookies
})

server.register(fastifySession, {
    secret: process.env.SESSION_SECRET || 'a-very-long-and-secret-keAGFAGAWGAEGAGEAGSy',
    cookie: { secure: false }
});

server.register(fastifyJWT, {
    secret: process.env.JWT_SECRET || 'another-very-long-and-secretAGEGEAGAEG-key'
});

server.decorate('authenticate', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
        await request.jwtVerify();
    } catch (err) {
        reply.send(err);
    }
});

server.register(webauthnRoutes); // Register the webauthn routes

server.register(fastifyStatic, {
    root: path.join(__dirname, 'public'),
    prefix: '/', // optional: default '/'
});

server.get('/profile', {
    preHandler: server.authenticate
}, async (request, reply) => {
    const user = request.user as { email: string };
    return { email: user.email, message: 'This is a protected route' };
});

server.get('/', async (request, reply) => {
    return reply.sendFile('index.html');
});

server.listen({ port: 3000 }, (err, address) => {
    if (err) {
        console.error(err);
        process.exit(1);
    }
    console.log(`Server listening at ${address}`);
});

