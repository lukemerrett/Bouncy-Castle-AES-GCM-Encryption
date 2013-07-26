namespace AESGCMInBouncyCastle.Cryptography
{
    #region

    using System;
    using System.IO;
    using System.Text;

    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Engines;
    using Org.BouncyCastle.Crypto.Modes;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Security;

    #endregion

    /// <summary>
    /// Code taken from this Stack question: 
    /// http://codereview.stackexchange.com/questions/14892/review-of-simplified-secure-encryption-of-a-string
    /// 
    /// The below code uses AES GCM using a 256bit key.
    /// 
    /// A non secret payload byte[] can be provided as well that won't be encrypted but will be authenticated with GCM.
    /// </summary>
    public class EncryptionService : IEncryptionService
    {
        #region Constants and Fields

        private const int KEY_BIT_SIZE = 256;

        private const int MAC_BIT_SIZE = 128;

        private const int NONCE_BIT_SIZE = 128;

        private readonly SecureRandom _random;

        #endregion

        #region Constructors and Destructors

        public EncryptionService()
        {
            _random = new SecureRandom();
        }

        #endregion

        #region Public Methods and Operators

        /// <summary>
        /// Simple Decryption & Authentication (AES-GCM) of a UTF8 Message
        /// </summary>
        /// <param name="encryptedMessage">The encrypted message.</param>
        /// <param name="key">The base 64 encoded 256 bit key.</param>
        /// <param name="nonSecretPayloadLength">Length of the optional non-secret payload.</param>
        /// <returns>Decrypted Message</returns>
        public string DecryptWithKey(string encryptedMessage, string key, int nonSecretPayloadLength = 0)
        {
            if (string.IsNullOrEmpty(encryptedMessage))
            {
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");
            }

            var decodedKey = Convert.FromBase64String(key);

            var cipherText = Convert.FromBase64String(encryptedMessage);

            var plaintext = DecryptWithKey(cipherText, decodedKey, nonSecretPayloadLength);

            return Encoding.UTF8.GetString(plaintext);
        }

        /// <summary>
        /// Simple Encryption And Authentication (AES-GCM) of a UTF8 string.
        /// </summary>
        /// <param name="messageToEncrypt">The string to be encrypted.</param>
        /// <param name="key">The base 64 encoded 256 bit key.</param>
        /// <param name="nonSecretPayload">Optional non-secret payload.</param>
        /// <returns>
        /// Encrypted Message
        /// </returns>
        /// <exception cref="System.ArgumentException">Secret Message Required!;secretMessage</exception>
        /// <remarks>
        /// Adds overhead of (Optional-Payload + BlockSize(16) + Message +  HMac-Tag(16)) * 1.33 Base64
        /// </remarks>
        public string EncryptWithKey(string messageToEncrypt, string key, byte[] nonSecretPayload = null)
        {
            if (string.IsNullOrEmpty(messageToEncrypt))
            {
                throw new ArgumentException("Secret Message Required!", "messageToEncrypt");
            }

            var decodedKey = Convert.FromBase64String(key);

            var plainText = Encoding.UTF8.GetBytes(messageToEncrypt);
            var cipherText = EncryptWithKey(plainText, decodedKey, nonSecretPayload);
            return Convert.ToBase64String(cipherText);
        }

        /// <summary>
        /// Helper that generates a random new key on each call.
        /// </summary>
        /// <returns>Base 64 encoded string</returns>
        public string NewKey()
        {
            var key = new byte[KEY_BIT_SIZE / 8];
            _random.NextBytes(key);
            return Convert.ToBase64String(key);
        }

        #endregion

        #region Methods

        private byte[] DecryptWithKey(byte[] encryptedMessage, byte[] key, int nonSecretPayloadLength = 0)
        {
            //User Error Checks
            if (key == null || key.Length != KEY_BIT_SIZE / 8)
            {
                throw new ArgumentException(String.Format("Key needs to be {0} bit!", KEY_BIT_SIZE), "key");
            }

            if (encryptedMessage == null || encryptedMessage.Length == 0)
            {
                throw new ArgumentException("Encrypted Message Required!", "encryptedMessage");
            }

            using (var cipherStream = new MemoryStream(encryptedMessage))
            using (var cipherReader = new BinaryReader(cipherStream))
            {
                //Grab Payload
                var nonSecretPayload = cipherReader.ReadBytes(nonSecretPayloadLength);

                //Grab Nonce
                var nonce = cipherReader.ReadBytes(NONCE_BIT_SIZE / 8);

                var cipher = new GcmBlockCipher(new AesFastEngine());
                var parameters = new AeadParameters(new KeyParameter(key), MAC_BIT_SIZE, nonce, nonSecretPayload);
                cipher.Init(false, parameters);

                //Decrypt Cipher Text
                var cipherText = cipherReader.ReadBytes(encryptedMessage.Length - nonSecretPayloadLength - nonce.Length);
                var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];

                try
                {
                    var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
                    cipher.DoFinal(plainText, len);
                }
                catch (InvalidCipherTextException)
                {
                    //Return null if it doesn't authenticate
                    return null;
                }

                return plainText;
            }
        }

        private byte[] EncryptWithKey(byte[] secretMessage, byte[] key, byte[] nonSecretPayload = null)
        {
            //User Error Checks
            if (key == null || key.Length != KEY_BIT_SIZE / 8)
            {
                throw new ArgumentException(String.Format("Key needs to be {0} bit!", KEY_BIT_SIZE), "key");
            }

            if (secretMessage == null || secretMessage.Length == 0)
            {
                throw new ArgumentException("Secret Message Required!", "secretMessage");
            }

            //Non-secret Payload Optional
            nonSecretPayload = nonSecretPayload ?? new byte[] { };

            //Using random nonce large enough not to repeat
            var nonce = new byte[NONCE_BIT_SIZE / 8];
            _random.NextBytes(nonce, 0, nonce.Length);

            var cipher = new GcmBlockCipher(new AesFastEngine());
            var parameters = new AeadParameters(new KeyParameter(key), MAC_BIT_SIZE, nonce, nonSecretPayload);
            cipher.Init(true, parameters);

            //Generate Cipher Text With Auth Tag
            var cipherText = new byte[cipher.GetOutputSize(secretMessage.Length)];
            var len = cipher.ProcessBytes(secretMessage, 0, secretMessage.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);

            //Assemble Message
            using (var combinedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(combinedStream))
                {
                    //Prepend Authenticated Payload
                    binaryWriter.Write(nonSecretPayload);
                    //Prepend Nonce
                    binaryWriter.Write(nonce);
                    //Write Cipher Text
                    binaryWriter.Write(cipherText);
                }
                return combinedStream.ToArray();
            }
        }

        #endregion
    }
}