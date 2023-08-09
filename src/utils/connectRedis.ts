import { createClient } from 'redis';
import config from 'config';

const redisUrl = config.get<string>('redisUri');

const redisClient = createClient({
  url: redisUrl,
});

const connectRedis = async () => {
  try {
    await redisClient.connect();
  } catch (error: any) {
    console.error(error.message);
    setTimeout(connectRedis, 5000);
  }
};

connectRedis();

redisClient.on('connect', () => console.log('Connected to redis'));

redisClient.on('error', (err) => console.error(err));

export default redisClient;
