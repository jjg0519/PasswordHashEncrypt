// --------------------------------------------------------------------------------------------------------------------
// <copyright file="HashPasswordUnitTest.cs" company="pzcast">
//   (C) 2015 pzcast. All rights reserved.
// </copyright>
// <summary>
//   The hash password unit test.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace PasswordHashEncrypt.UnitTest
{
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    
    /// <summary>
    /// The hash password unit test.
    /// </summary>
    [TestClass]
    public class HashPasswordUnitTest
    {
        #region Fields

        /// <summary>
        /// The hash password.
        /// </summary>
        private IHashPassword hashPassword;

        #endregion

        #region Public Methods and Operators

        /// <summary>
        /// The initialize.
        /// </summary>
        [TestInitialize]
        public void Initialize()
        {
            // this.hashPassword = new SHA256HashPassword();
            this.hashPassword = new SHA512HashPassword();
        }

        /// <summary>
        /// The validation test.
        /// </summary>
        [TestMethod]
        public void ValidationTest()
        {
            const string TestPassword = "abc123";

            string hashValue = this.hashPassword.Generate(TestPassword);
            Assert.IsNotNull(hashValue);

            bool result = this.hashPassword.Validate(TestPassword, hashValue);
            Assert.IsTrue(result);
        }

        #endregion
    }
}