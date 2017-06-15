using System;
using System.Linq;
using System.Security.Cryptography;

namespace Microsoft.Azure.KeyVault.WebKey
{
    /// <summary>
    /// EC paramters class. This is supported in .NET framework v4.7 but not in the current .net version.
    /// </summary>
    public class ECParameters
    {
        /// <summary>
        /// X coordinate for the Elliptic Curve point.
        /// </summary>
        public byte[] X { get; set; }

        /// <summary>
        /// Y coordinate for the Elliptic Curve point.
        /// </summary>
        public byte[] Y { get; set; }

        /// <summary>
        /// ECC private key.
        /// </summary>
        public byte[] D { get; set; }

        /// <summary>
        /// The curve for Elliptic Curve Cryptography(ECC) algorithms
        /// </summary>
        public string Curve { get; set; }

        public byte[] GetKeyBlob(bool includePrivateParameters)
        {
            if (X == null || Y == null)
                throw new ArgumentException("Invalid EC parameter(s).");

            KeyBlobMagicNumber magic;
            int length = X.Length;

            if (includePrivateParameters)
            {
                if (D == null)
                    throw new CryptographicException("Private key material D is missing.");

                switch (Curve)
                {
                    case JsonWebKeyECCurve.P256:
                        magic = KeyBlobMagicNumber.BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
                        break;
                    case JsonWebKeyECCurve.P384:
                        magic = KeyBlobMagicNumber.BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
                        break;
                    case JsonWebKeyECCurve.P521:
                        magic = KeyBlobMagicNumber.BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
                        break;
                    default:
                        throw new CryptographicException(string.Format("Invalid curve {0}.", Curve));
                }
            }
            else
            {
                switch (Curve)
                {
                    case JsonWebKeyECCurve.P256:
                        magic = KeyBlobMagicNumber.BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
                        break;
                    case JsonWebKeyECCurve.P384:
                        magic = KeyBlobMagicNumber.BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
                        break;
                    case JsonWebKeyECCurve.P521:
                        magic = KeyBlobMagicNumber.BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
                        break;
                    default:
                        throw new CryptographicException(string.Format("Invalid curve {0}.", Curve));
                }
            }
            var bMagic = BitConverter.GetBytes((int)magic);
            var bLength = BitConverter.GetBytes(length);
            return includePrivateParameters ? ConcatBytes(bMagic, bLength, X, Y, D) : ConcatBytes(bMagic, bLength, X, Y);
        }

        private byte[] ConcatBytes(params byte[][] bytes)
        {
            byte[] result = new byte[bytes.Sum(b => b.Length)];
            int offset = 0;
            foreach (byte[] b in bytes)
            {
                Buffer.BlockCopy(b, 0, result, offset, b.Length);
                offset += b.Length;
            }
            return result;
        }
    }
}
