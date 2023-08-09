import cookieParser from 'cookie-parser';
import express from 'express';
import cors from 'cors';

const app = express();

export const corsOptions = {
  origin: ['https://studio.apollographql.com', 'http://localhost:5000'],
  credentials: true,
};

app.use(cookieParser());
app.use(cors(corsOptions));

export default app;
