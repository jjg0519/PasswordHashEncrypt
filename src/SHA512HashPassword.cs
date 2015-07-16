// --------------------------------------------------------------------------------------------------------------------
// <copyright file="SHA512HashPassword.cs" company="pzcast">
//   (C) 2015 pzcast. All rights reserved.
// </copyright>
// <summary>
//   The sh a 512 hash password.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace PasswordHashEncrypt
{
    using System;
    using System.Security.Cryptography;

    /// <summary>
    /// The sh a 512 hash password.
    /// </summary>
    public class SHA512HashPassword : HashPasswordBase
    {
        #region Constants

        /// <summary>
        /// The hash byte length const.
        /// </summary>
        public const int HashByteLengthConst = 64;

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
            SHA512 service;

            try
            {
                service = new SHA512CryptoServiceProvider();
            }
            catch (PlatformNotSupportedException)
            {
                service = new SHA512Managed();
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