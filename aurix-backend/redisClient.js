const Redis = require('ioredis');
require('dotenv').config();

const redisUrl = process.env.UPSTASH_REDIS_URL;

let redis = null;

if (redisUrl) {
    redis = new Redis(redisUrl, {
        tls: {
            rejectUnauthorized: false
        },
        maxRetriesPerRequest: 3,
        retryStrategy(times) {
            if (times > 5) {
                console.error('[Redis] Too many retries. Giving up on this connection attempt.');
                return null; // stop retrying
            }
            const delay = Math.min(times * 200, 2000);
            console.warn(`[Redis] Reconnecting... attempt ${times} in ${delay}ms`);
            return delay;
        },
        enableReadyCheck: true,
        connectTimeout: 10000,
        lazyConnect: false,
    });

    redis.on('connect', () => console.log('[Redis] ✅ Connected to Upstash Redis successfully.'));
    redis.on('ready', () => console.log('[Redis] ✅ Redis client is ready to accept commands.'));
    redis.on('error', (err) => console.error('[Redis] ❌ Client Error:', err.message));
    redis.on('close', () => console.warn('[Redis] ⚠️  Connection closed.'));
    redis.on('reconnecting', (ms) => console.warn(`[Redis] ⚠️  Reconnecting in ${ms}ms...`));
} else {
    console.warn('[Redis] ⚠️  UPSTASH_REDIS_URL not set. Redis queue will be disabled. Scans will fail.');
}

module.exports = redis;
