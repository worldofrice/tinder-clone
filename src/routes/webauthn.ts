import { FastifyInstance } from 'fastify';
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const userAuthenticators = new Map<string, any>(); // In-memory storage for user authenticators

export default async function (fastify: FastifyInstance) {
    fastify.post('/webauthn/register/generate-options', async (request, reply) => {
        const { email } = request.body as { email: string };

        // Generate registration options
        const options = await generateRegistrationOptions({
            rpName: 'Tinder Clone',
            rpID: process.env.RP_ID || 'localhost',
            userID: new Uint8Array(Buffer.from(email)),
            userName: email,
            attestationType: 'none',
            authenticatorSelection: {
                residentKey: 'required',
                userVerification: 'preferred',
            },
        });

        reply.setCookie('currentChallenge', options.challenge);

        return options;
    });

    fastify.post('/webauthn/register/verify', async (request, reply) => {
        const { email, response } = request.body as { email: string, response: any };

        const expectedChallenge = request.cookies.currentChallenge;
        console.log('expectedChallenge', expectedChallenge);
        console.log("------------------------------")
        console.log(request.cookies)
        console.log("------------------------------")
        reply.setCookie('currentChallenge', "");

        try {
            const verification = await verifyRegistrationResponse({
                response,
                expectedChallenge: expectedChallenge || '',
                expectedOrigin: process.env.RP_ORIGIN || 'http://localhost:3000',
                expectedRPID: process.env.RP_ID || 'localhost',
            });

            if (verification.verified) {
                // Save the user and authenticator info to your database here
                if (verification.registrationInfo) {
                    userAuthenticators.set(email, {
                        credentialID: Buffer.from(verification.registrationInfo.credential.id).toString('base64'),
                        credentialPublicKey: Buffer.from(verification.registrationInfo.credential.publicKey).toString('base64'),
                        counter: verification.registrationInfo.credential.counter,
                    });
                } else {
                    reply.code(400).send({ error: 'Registration info is missing' });
                    return;
                }
                const token = fastify.jwt.sign({ email });

                return { token };
            } else {
                reply.code(400).send({ error: 'Registration failed' });
            }
        } catch (error) {
            console.error(error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });

    fastify.get('/webauthn/authenticate/generate-options', async (request, reply) => {
        const options = await generateAuthenticationOptions({
            rpID: process.env.RP_ID || 'localhost',
            allowCredentials: [], // You would typically load this from your database
            userVerification: 'preferred',
        });

        reply.setCookie('currentChallenge', options.challenge);

        return options;
    });

    fastify.post('/webauthn/authenticate/verify', async (request, reply) => {
        const { response, email } = request.body as { response: any, email: string };

        const expectedChallenge = request.cookies.currentChallenge;
        reply.setCookie('currentChallenge', "");

        console.log("USERS STORE \n", userAuthenticators)

        try {
            const user = userAuthenticators.get(email);
            console.log("user:", user)
            if (!user) {
                reply.code(400).send({ error: 'User not found' });
                return;
            }

            const mockAuthenticator = {
                credentialID: Buffer.from(user.credentialID, 'base64'),
                credentialPublicKey: Buffer.from(user.credentialPublicKey, 'base64'),
                counter: user.counter,
            };

            if (!response.response.clientDataJSON || !response.response.authenticatorData || !response.response.signature) {
                reply.code(400).send({ error: 'Invalid response format' });
                return;
            }

            console.log(mockAuthenticator)

            const webauthnCredential = {
                id: mockAuthenticator.credentialID.toString('base64'),
                type: 'public-key',
                rawId: mockAuthenticator.credentialID,
                response: {
                    clientDataJSON: Buffer.from(response.response.clientDataJSON, 'base64'),
                    authenticatorData: Buffer.from(response.response.authenticatorData, 'base64'),
                    signature: Buffer.from(response.response.signature, 'base64'),
                    userHandle: response.response.userHandle ? Buffer.from(response.response.userHandle, 'base64') : null,
                },
            };

            const verification = await verifyAuthenticationResponse({
                response,
                expectedChallenge: expectedChallenge || '',
                expectedOrigin: process.env.RP_ORIGIN || 'http://localhost:3000',
                expectedRPID: process.env.RP_ID || 'localhost',
                credential: {
                    ...webauthnCredential,
                    publicKey: mockAuthenticator.credentialPublicKey,
                    counter: mockAuthenticator.counter,
                },
            });

            if (verification.verified) {
                // Update the authenticator's counter in your database here
                const token = fastify.jwt.sign({ email: email });
                return { token };
            } else {
                reply.code(400).send({ error: 'Authentication failed' });
            }
        } catch (error) {
            console.error(error);
            reply.code(500).send({ error: 'Internal server error' });
        }
    });
}

