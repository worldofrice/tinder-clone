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
    secret: process.env.COOKIE_SECRET || "my-secret", 
    hook: 'onRequest',
    parseOptions: {}
})

server.register(fastifySession, {
    secret: process.env.SESSION_SECRET || 'a-very-long-and-secret-keAGFAGAWGAEGAGEAGSy',
    cookie: { secure: false, sameSite: 'lax', maxAge: 900000, httpOnly: true },
});

server.register(fastifyJWT, {
    secret: process.env.JWT_SECRET || 'another-very-long-and-secretAGEGEAGAEG-key'
});

server.register(fastifyStatic, {
    root: path.join(__dirname, 'public'),
    prefix: '/', // optional: default '/'
});

server.decorate('authenticate', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
        await request.jwtVerify();
    } catch (err) {
        reply.send(err);
    }
});

server.register(webauthnRoutes); // Register the webauthn routes

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

