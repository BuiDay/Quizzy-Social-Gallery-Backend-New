import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';

export type UserDocument = User & Document;

@Schema({ timestamps: true })
export class User {
  @Prop({ required: true })
  name: string;

  @Prop({
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  })
  email: string;

  @Prop({
    required: true,
    minlength: 6,
    select: false,
  })
  password: string;

  @Prop({
    type: {
      public_id: { type: String },
      url: { type: String },
    },
    default: {},
  })
  avatar: {
    public_id?: string;
    url?: string;
  };

  @Prop({ type: Types.ObjectId, ref: 'Cart' })
  carts: Types.ObjectId;

  @Prop({ type: [String], default: ['user'] })
  role: string[];

  @Prop({ default: false })
  isVerified: boolean;

  @Prop({ type: [{ type: Types.ObjectId, ref: 'Product' }], default: [] })
  products: Types.ObjectId[];

  @Prop()
  passwordResetToken?: string;

  @Prop()
  passwordResetExpires?: number;

  @Prop()
  passwordChangedAt?: number;

  comparePassword: (password: string) => Promise<boolean>;
  signAccessToken: () => string;
  signRefreshToken: () => string;
}

export const UserSchema = SchemaFactory.createForClass(User);

UserSchema.pre<UserDocument>('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

UserSchema.methods.comparePassword = async function (
  enteredPassword: string,
): Promise<boolean> {
  return bcrypt.compare(enteredPassword, this.password);
};

UserSchema.methods.signAccessToken = function () {
  return jwt.sign(
    { id: this._id },
    process.env.ACCESS_TOKEN || '',
    { expiresIn: '5m' },
  );
};

UserSchema.methods.signRefreshToken = function () {
  return jwt.sign(
    { id: this._id },
    process.env.REFRESH_TOKEN || '',
    { expiresIn: '3d' },
  );
};
