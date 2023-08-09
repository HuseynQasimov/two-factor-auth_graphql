import mongoose from 'mongoose';
import config from 'config';

const localUri = config.get<string>('dbUri');

async function connectDB() {
  try {
    await mongoose.connect(localUri);
    console.log('Connected to database');
  } catch (error: any) {
    console.error(error.message);
    setTimeout(connectDB, 5000);
  }
}

export default connectDB;
