import { Field, InputType, ObjectType } from 'type-graphql';
import { IsEmail, MaxLength, MinLength } from 'class-validator';

@InputType()
export class SignUpInput {
  @IsEmail()
  @Field(() => String)
  email: string;

  @MinLength(6, { message: 'Password must be at least 6 characters long' })
  @MaxLength(24, { message: 'Password must be at most 24 characters long' })
  @Field(() => String)
  password: string;

  @Field(() => String)
  passwordConfirm: string | undefined;
}

@InputType()
export class LoginInput {
  @IsEmail()
  @Field(() => String)
  email: string;

  @Field(() => String)
  password: string;

  @Field(() => String)
  otp: string;
}

@InputType()
export class ChangePasswordInput {
  @Field(() => String)
  oldPassword: string;

  @MinLength(6, { message: 'Password must be at least 6 characters long' })
  @MaxLength(24, { message: 'Password must be at most 24 characters long' })
  @Field(() => String)
  newPassword: string;
}

@ObjectType()
export class UserData {
  @Field(() => String)
  readonly _id: string;

  @Field(() => String, { nullable: true })
  readonly id: string;

  @Field(() => String)
  email: string;

  @Field(() => String)
  qrCode: string;

  @Field(() => Date)
  createdAt: Date;

  @Field(() => Date)
  updatedAt: Date;
}

@ObjectType()
export class UserResponse {
  @Field(() => UserData)
  user: UserData;
}

@ObjectType()
export class LoginResponse {
  @Field(() => String)
  access_token: string;
}
