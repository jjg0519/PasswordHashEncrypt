// --------------------------------------------------------------------------------------------------------------------
// <copyright file="HashPasswordBase.cs" company="pzcast">
//   (C) 2015 pzcast. All rights reserved.
// </copyright>
// <summary>
//   The hash password base.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace PasswordHashEncrypt
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;

    /// <summary>
    /// The hash password base.
    /// </summary>
    public abstract class HashPasswordBase : IHashPassword
    {
        #region Public Properties

        /// <summary>
        /// Gets the hash byte length.
        /// </summary>
        public int HashByteLength
        {
            get
            {
                return this.GetHashByteLength();
            }
        }

        #endregion

        #region Public Methods and Operators

        /// <summary>
        /// The generate.
        /// </summary>
        /// <param name="password">
        /// The password.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        public string Generate(string password)
        {
            byte[] salt = this.GenerateSalt();
            byte[] hash = this.Generate(password, salt);
            return string.Format("{0}:{1}", Convert.ToBase64String(salt), Convert.ToBase64String(hash));
        }

        /// <summary>
        /// The validate.
        /// </summary>
        /// <param name="password">
        /// The password.
        /// </param>
        /// <param name="hashValue">
        /// The hash value.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/>.
        /// </returns>
        public bool Validate(string password, string hashValue)
        {
            string[] splits = hashValue.Split(':');
            if (splits.Length == 2)
            {
                byte[] salt = Convert.FromBase64String(splits[0]);
                byte[] hash = Convert.FromBase64String(splits[1]);

                return this.Validate(password, salt, hash);
            }

            return false;
        }

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
        protected abstract byte[] ComputeHash(byte[] buffer);

        /// <summary>
        /// The generate.
        /// </summary>
        /// <param name="password">
        /// The password.
        /// </param>
        /// <param name="salt">
        /// The salt.
        /// </param>
        /// <returns>
        /// The <see cref="byte[]"/>.
        /// </returns>
        protected byte[] Generate(string password, byte[] salt)
        {
            byte[] bytes = BlockCopy(password);
            byte[] combined = Combine(salt, bytes);
            return this.ComputeHash(combined);
        }

        /// <summary>
        /// The generate salt.
        /// </summary>
        /// <returns>
        /// The <see cref="byte[]"/>.
        /// </returns>
        protected byte[] GenerateSalt()
        {
            return RandomSalt(this.HashByteLength);
        }

        /// <summary>
        /// The get hash byte length.
        /// </summary>
        /// <returns>
        /// The <see cref="int"/>.
        /// </returns>
        protected abstract int GetHashByteLength();

        /// <summary>
        /// The validate.
        /// </summary>
        /// <param name="password">
        /// The password.
        /// </param>
        /// <param name="salt">
        /// The salt.
        /// </param>
        /// <param name="goodHash">
        /// The good hash.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/>.
        /// </returns>
        protected bool Validate(string password, byte[] salt, byte[] goodHash)
        {
            byte[] hash = this.Generate(password, salt);
            return SlowEquals(hash, goodHash);
        }

        /// <summary>
        /// The block copy.
        /// </summary>
        /// <param name="input">
        /// The input.
        /// </param>
        /// <returns>
        /// The <see cref="byte[]"/>.
        /// </returns>
        private static byte[] BlockCopy(string input)
        {
            var bytes = new byte[input.Length * sizeof(char)];
            Buffer.BlockCopy(input.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        /// <summary>
        /// The combine.
        /// </summary>
        /// <param name="a">
        /// The a.
        /// </param>
        /// <param name="b">
        /// The b.
        /// </param>
        /// <returns>
        /// The <see cref="byte[]"/>.
        /// </returns>
        private static byte[] Combine(byte[] a, byte[] b)
        {
            return a.Concat(b).ToArray();
        }

        /// <summary>
        /// The random salt.
        /// </summary>
        /// <param name="length">
        /// The length.
        /// </param>
        /// <returns>
        /// The <see cref="byte[]"/>.
        /// </returns>
        private static byte[] RandomSalt(int length)
        {
            var rng = new RNGCryptoServiceProvider();
            var salt = new byte[length];
            rng.GetBytes(salt);
            return salt;
        }

        /// <summary>
        /// The slow equals.
        /// </summary>
        /// <param name="a">
        /// The a.
        /// </param>
        /// <param name="b">
        /// The b.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/>.
        /// </returns>
        private static bool SlowEquals(byte[] a, byte[] b)
        {
            uint diff = (uint)a.Length ^ (uint)b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++)
            {
                diff |= (uint)(a[i] ^ b[i]);
            }

            return diff == 0;
        }

        #endregion
    }
}