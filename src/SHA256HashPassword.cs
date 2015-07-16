// --------------------------------------------------------------------------------------------------------------------
// <copyright file="SHA256HashPassword.cs" company="pzcast">
//   (C) 2015 pzcast. All rights reserved.
// </copyright>
// <summary>
//   The sh a 256 hash password.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace PasswordHashEncrypt
{
    using System;
    using System.Security.Cryptography;

    /// <summary>
    /// The sh a 256 hash password.
    /// </summary>
    public class SHA256HashPassword : HashPasswordBase
    {
        #region Constants

        /// <summary>
        /// The hash byte length const.
        /// </summary>
        public const int HashByteLengthConst = 32;

        #endregion

        #region Methods

        /// <summary>
        /// The compute hash.
        /// </summary>
        /// <param name="buffer">
        /// The buffer.
        /// </param>
        /// <returns>
        /// The <see cref="byte[]"/>.
        /// </returns>
        protected override byte[] ComputeHash(byte[] buffer)
        {
            SHA256 service;

            try
            {
                service = new SHA256CryptoServiceProvider();
            }
            catch (PlatformNotSupportedException)
            {
                service = new SHA256Managed();
            }

            return service.ComputeHash(buffer);
        }

        /// <summary>
        /// The get hash byte length.
        /// </summary>
        /// <returns>
        /// The <see cref="int"/>.
        /// </returns>
        protected override int GetHashByteLength()
        {
            return HashByteLengthConst;
        }

        #endregion
    }
}