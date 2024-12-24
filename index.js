//
// Proxy Backblaze S3 compatible API requests, sending notifications to a webhook
//
// Adapted from https://github.com/obezuk/worker-signed-s3-template
//
import { AwsClient } from 'aws4fetch';
import { isBot, getBotType, getBlockedResponse } from './bots.js';

// Protected paths that should return 403
const PROTECTED_PATHS = new Set([
    '/',
    '/admin',
    '/administrator',
    '/wp-admin',
    '/phpmyadmin',
    '/dashboard',
    '/cp',
    '/controlpanel',
    '/panel',
    '/webadmin',
    '/adminpanel',
    '/admin-panel',
    '/manage',
    '/management',
    '/administration',
    '/backend',
    '/account',
    '/login',
    '/wp-login',
    '/wp-admin',
    '/user',
    '/cms',
    '/.env',
    '/config',
    '/.git',
    '/.ssh',
    '/backup',
    '/db',
    '/database',
    '/sql',
    '/server-status',
    '/nginx-status'
]);

/**
 * Function to check if a path should be blocked.
 */
function isProtectedPath(path) {
    // Normalize the path
    const normalizedPath = path.toLowerCase().replace(/\/+/g, '/');
    
    // Check exact matches
    if (PROTECTED_PATHS.has(normalizedPath)) return true;
    
    // Check if path starts with any protected paths
    return Array.from(PROTECTED_PATHS).some(blocked => 
        normalizedPath.startsWith(blocked + '/') || 
        normalizedPath.includes('/.' + blocked + '/')
    );
}


// URL needs colon suffix on protocol, and port as a string
const HTTPS_PROTOCOL = 'https:';
const HTTPS_PORT = '443';
// How many times to retry a range request where the response is missing content-range
const RANGE_RETRY_ATTEMPTS = 3;

// Memoized AWS client creation
let awsClient = null;

// Untouchable headers as a Set for O(1) lookup
const UNTOUCHABLE_HEADERS = new Set([
    'x-forwarded-proto', // Headers not passed upstream
    'x-real-ip',
    'accept-encoding' // Cloudflare modifies this header
]);

/**
 * Function to get awsClient.
 */
function getAwsClient(keyId, secretKey) {
    if (!awsClient) {
        awsClient = new AwsClient({
            accessKeyId: keyId,
            secretAccessKey: secretKey,
            service: "s3"
        });
    }
    return awsClient;
}

/**
 * Filters out headers that shouldn't be signed or passed upstream.
 */
function filterHeaders(headers, allowedHeaders) {

    const filtered = new Headers();
    for (const [key, value] of headers) {
        if (!UNTOUCHABLE_HEADERS.has(key) && 
            !key.startsWith('cf-') &&
            (!allowedHeaders || allowedHeaders.has(key))) {
            filtered.append(key, value);
        }
    }
    return filtered;
}

/**
 * Creates a response for HEAD requests with the same headers and status but no body.
 */
function createHeadResponse(response) {
    return new Response(null, {
        headers: response.headers,
        status: response.status,
        statusText: response.statusText
    });
}

/**
 * Determines if the request is for listing a bucket's contents.
 */
function isListBucketRequest(bucketName, path) {
    if (!path) return true;
    return bucketName === "$path" && !path.includes('/');
}
// function isListBucketRequest(env, path) {
//     const pathSegments = path.split('/');
//     return (
//         (env.BUCKET_NAME === "$path" && pathSegments.length < 2) || 
//         (env.BUCKET_NAME !== "$path" && path.length === 0)
//     );
// }

/**
 * Sends a notification to a webhook with the provided payload.
 */
async function sendWebhookNotification(webhookUrl, payload) {
    if (!webhookUrl) return;

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            signal: controller.signal
        });

        clearTimeout(timeoutId);
    } catch (error) {
        console.error(`Webhook notification failed: ${error.message}`);
    }
}

export default {
    async fetch(request, env) {

        // Bot detection
        const userAgent = request.headers.get('user-agent');
        if (isBot(userAgent)) {
            const botType = getBotType(userAgent);
            await sendWebhookNotification(env.WEBHOOK_URL, {
                type: 'bot_detected',
                botType: botType,
                userAgent: userAgent,
                url: request.url
            });
            return getBlockedResponse(botType);
        }

        const { BUCKET_NAME, B2_ENDPOINT, B2_APPLICATION_KEY_ID, B2_APPLICATION_KEY, 
                ALLOW_LIST_BUCKET, RCLONE_DOWNLOAD, WEBHOOK_URL, ALLOWED_HEADERS } = env;
        // URL parsing optimisation
        const url = new URL(request.url);
        // Early method validation
        if (request.method !== 'GET' && request.method !== 'HEAD') {
            return new Response("Method Not Allowed", { status: 405 });
        }

        // Check for protected paths
        if (isProtectedPath(url.pathname)) {
            return new Response("Forbidden", { 
                status: 403,
                headers: {
                    'X-Frame-Options': 'DENY',
                    'X-Content-Type-Options': 'nosniff',
                    'X-XSS-Protection': '1; mode=block'
                }
            });
        }


        url.protocol = HTTPS_PROTOCOL;
        url.port = HTTPS_PORT;

        const path = url.pathname.slice(1).replace(/\/$/, '');

        // Early bucket listing check
        if (isListBucketRequest(BUCKET_NAME, path) && ALLOW_LIST_BUCKET !== "true") {
            return new Response("Not Found", { status: 404 });
        }

        // RCLONE validation
        if (BUCKET_NAME === "$path" && RCLONE_DOWNLOAD === 'true') {
            return new Response("Configuration Error: RCLONE_DOWNLOAD is incompatible with BUCKET_NAME=$path", { 
                status: 500 
            });
        }

        // Optimised hostname determination
        url.hostname = BUCKET_NAME === "$path" ? B2_ENDPOINT :
                      BUCKET_NAME === "$host" ? `${url.hostname.split('.')[0]}.${B2_ENDPOINT}` :
                      `${BUCKET_NAME}.${B2_ENDPOINT}`;

        // Convert ALLOWED_HEADERS to Set for faster lookup
        const allowedHeadersSet = ALLOWED_HEADERS ? new Set(ALLOWED_HEADERS) : null;
        const headers = filterHeaders(request.headers, allowedHeadersSet);
        
        // Use memoized AWS client
        const client = getAwsClient(B2_APPLICATION_KEY_ID, B2_APPLICATION_KEY);

        if (RCLONE_DOWNLOAD === 'true') {
            url.pathname = path.replace(/^file\//, "");
        }

        const signedRequest = await client.sign(url.toString(), {
            method: request.method,
            headers: headers
        });

        // Handle range requests with optimised retry logic
        if (signedRequest.headers.has("range")) {
            let lastError = null;
            
            for (let attempt = 0; attempt < RANGE_RETRY_ATTEMPTS; attempt++) {
                try {
                    const response = await fetch(signedRequest.url, {
                        method: signedRequest.method,
                        headers: signedRequest.headers
                    });

                    if (response.headers.has("content-range")) {
                        return request.method === 'HEAD' ? createHeadResponse(response) : response;
                    }
                    
                    lastError = new Error("Missing content-range header");
                } catch (error) {
                    lastError = error;
                }
            }

            console.error(`Range request failed: ${lastError.message}`);
            await sendWebhookNotification(WEBHOOK_URL, { 
                error: lastError.message, 
                url: signedRequest.url 
            });
        }

        // Standard request handling
        try {
            const response = await fetch(signedRequest);
            return request.method === 'HEAD' ? createHeadResponse(response) : response;
        } catch (error) {
            console.error(`Fetch failed: ${error.message}`);
            await sendWebhookNotification(WEBHOOK_URL, { 
                error: error.message, 
                url: signedRequest.url 
            });
            return new Response("Internal Server Error", { status: 500 });
        }
    }
};
