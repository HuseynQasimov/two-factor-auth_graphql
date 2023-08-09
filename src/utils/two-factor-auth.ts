import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

export const generateOTP = async () => {
  const secretKey = speakeasy.generateSecret();

  const qrCode = await QRCode.toDataURL(secretKey.otpauth_url!);

  return { secretKey, qrCode };
};
