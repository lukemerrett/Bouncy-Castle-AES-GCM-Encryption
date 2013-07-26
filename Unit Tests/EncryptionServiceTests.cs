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
        public void NewKey_MethodRun_ReturnsRandomKey()
        {
            var twoFiveSixBitKey = _encryptionService.NewKey();

            var stringKey = Convert.ToBase64String(twoFiveSixBitKey);

            Assert.IsFalse(string.IsNullOrWhiteSpace(stringKey));
        }

        #endregion
    }
}