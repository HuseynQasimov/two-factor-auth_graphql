import 'reflect-metadata';
import dotenv from 'dotenv';
dotenv.config();
import { ApolloServer } from 'apollo-server-express';
import { buildSchema } from 'type-graphql';
import config from 'config';
import app, { corsOptions } from './app';
import { resolvers } from './resolvers/index';
import deserializeUser from './middlewares/deserializeUser';
import connectDB from './utils/connectDB';

const bootstrap = async () => {
  const schema = await buildSchema({
    resolvers,
    dateScalarMode: 'isoDate',
  });

  const apolloServer = new ApolloServer({
    schema,
    csrfPrevention: true,
    context: ({ req, res }) => ({ req, res, deserializeUser }),
  });

  await apolloServer.start();
  apolloServer.applyMiddleware({ app, cors: corsOptions });

  const port = config.get<number>('PORT') || 5000;

  app.listen(port, () => {
    connectDB();
    console.log(`Server is running on http://localhost:${port}/graphql`);
  });
};

bootstrap().catch((error) => {
  console.error(error);
});
