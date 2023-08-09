import {
  getModelForClass,
  prop,
  pre,
  ModelOptions,
  Severity,
  index,
} from '@typegoose/typegoose';
import bcrypt from 'bcryptjs';
import config from 'config';

@pre<User>('save', async function (next) {
  if (!this.isModified('password')) return next();

  this.password = await bcrypt.hash(
    this.password,
    config.get<number>('costFactor')
  );
  this.passwordConfirm = undefined;
  return next();
})
@ModelOptions({
  schemaOptions: {
    timestamps: true,
  },
  options: {
    allowMixed: Severity.ALLOW,
  },
})
@index({ email: 1 })
export class User {
  readonly _id: string;

  @prop({ required: true, unique: true, lowercase: true })
  email: string;

  @prop({ required: true })
  password: string;

  @prop({ required: true })
  passwordConfirm: string | undefined;

  @prop()
  otpSecretKey: string;

  @prop()
  qrCode: string;
}

const UserModel = getModelForClass<typeof User>(User);
export default UserModel;
