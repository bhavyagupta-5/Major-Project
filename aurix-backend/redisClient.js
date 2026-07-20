const Redis = require('ioredis');
require('dotenv').config();

const redisUrl = process.env.UPSTASH_REDIS_URL;

let redis = null;

if (redisUrl) {
    redis = new Redis(redisUrl);
    redis.on('error', (err) => console.error('Redis Client Error', err));
} else {
    console.warn("Missing UPSTASH_REDIS_URL in environment variables. Redis queue will not work.");
}

module.exports = redis;
