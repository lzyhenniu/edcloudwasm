import { handleRequest } from '../src/worker-core.js';

export async function onRequest(context) {
    return handleRequest(context.request, context.env);
}
