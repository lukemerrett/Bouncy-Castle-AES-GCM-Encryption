namespace AESGCMInBouncyCastle.Unit_Tests
{
    #region

    using System;

    using Cryptography;

    using NUnit.Framework;

    #endregion

    [TestFixture]
    public class EncryptionServiceTests
    {
        #region Constants and Fields

        private IEncryptionService _encryptionService;

        #endregion

        #region Public Methods and Operators

        [SetUp]
        public void TestSetUp()
        {
            _encryptionService = new EncryptionService();
        }

        [Test]
        public void EncryptWithKey_EmptyMessageProvided_ArgumentExceptionThrown()
        {
            string message = string.Empty;

            var key = _encryptionService.NewKey();

            Assert.Throws<ArgumentException>(() => _encryptionService.EncryptWithKey(message, key));
        }

        [Test]
        public void EncryptWithKey_KeyProvidedIsNotA256BitKey_ArgumentExceptionThrown()
        {
            const string Message = "EncryptMe";

            var random = new Random();
            var key = new Byte[16];

            random.NextBytes(key);

            var encodedKey = Convert.ToBase64String(key);

            Assert.Throws<ArgumentException>(() => _encryptionService.EncryptWithKey(Message, encodedKey));
        }

        [Test]
        public void EncryptWithKey_NullKeyProvided_ArgumentNullExceptionThrown()
        {
            const string Message = "EncryptMe";

            Assert.Throws<ArgumentNullException>(() => _encryptionService.EncryptWithKey(Message, null));
        }

        [Test]
        public void EncryptWithKey_NullMessageProvided_ArgumentExceptionThrown()
        {
            var key = _encryptionService.NewKey();

            Assert.Throws<ArgumentException>(() => _encryptionService.EncryptWithKey(null, key));
        }

        [Test]
        public void EncryptWithKey_ValidKeyAndMessageProvided_MessageIsEncrypted()
        {
            const string Message = "EncryptMe";

            var key = _encryptionService.NewKey();

            var encryptedText = _encryptionService.EncryptWithKey(Message, key);

            Assert.IsFalse(string.IsNullOrEmpty(encryptedText));
        }

        [Test]
        public void DecryptWithKey_EmptyMessageProvided_ArgumentExceptionThrown()
        {
            var message = string.Empty;

            var key = _encryptionService.NewKey();

            Assert.Throws<ArgumentException>(() => _encryptionService.DecryptWithKey(message, key));
        }

        [Test]
        public void DecryptWithKey_NullKeyProvided_ArgumentNullExceptionThrown()
        {
            const string Message = "DecryptMe";

            Assert.Throws<ArgumentNullException>(() => _encryptionService.DecryptWithKey(Message, null));
        }

        [Test]
        public void DecryptWithKey_NullMessageProvided_ArgumentExceptionThrown()
        {
            var key = _encryptionService.NewKey();

            Assert.Throws<ArgumentException>(() => _encryptionService.DecryptWithKey(null, key));
        }

        [Test]
        public void DecryptWithKey_KeyProvidedIsNotA256BitKey_FormatExceptionThrown()
        {
            const string Message = "DecryptMe";

            var random = new Random();
            var key = new Byte[16];

            random.NextBytes(key);

            var encodedKey = Convert.ToBase64String(key);

            Assert.Throws<FormatException>(() => _encryptionService.DecryptWithKey(Message, encodedKey));
        }

        [Test]
        public void DecryptWithKey_ValidKeyAndMessageProvided_ArgumentExceptionThrown()
        {
            const string Message = "EncryptMe";

            var key = _encryptionService.NewKey();

            var encryptedString = _encryptionService.EncryptWithKey(Message, key);

            var decryptedString = _encryptionService.DecryptWithKey(encryptedString, key);

            Assert.AreEqual(Message, decryptedString);
        }

        [Test]
        public void NewKey_KeyReturned_KeyCanBeCastToABase64String()
        {
            var key = _encryptionService.NewKey();

            Assert.IsFalse(string.IsNullOrWhiteSpace(key));
        }

        [Test]
        public void NewKey_KeyReturned_KeyIs256BitKey()
        {
            var key = _encryptionService.NewKey();

            var decodedKey = Convert.FromBase64String(key);

            var numberOfBits = decodedKey.Length * 8;

            Assert.AreEqual(256, numberOfBits);
        }

        #endregion
    }
}