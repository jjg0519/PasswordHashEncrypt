// --------------------------------------------------------------------------------------------------------------------
// <copyright file="IHashPassword.cs" company="pzcast">
//   (C) 2015 pzcast. All rights reserved.
// </copyright>
// <summary>
//   The HashPassword interface.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace PasswordHashEncrypt
{
    /// <summary>
    /// The HashPassword interface.
    /// </summary>
    public interface IHashPassword
    {
        #region Public Properties

        /// <summary>
        /// Gets the hash byte length.
        /// </summary>
        int HashByteLength { get; }

        #endregion

        #region Public Methods and Operators

        /// <summary>
        /// The generate.
        /// </summary>
        /// <param name="passwordString">
        /// The password string.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        string Generate(string passwordString);

        /// <summary>
        /// The validate.
        /// </summary>
        /// <param name="passwordString">
        /// The password string.
        /// </param>
        /// <param name="hashValue">
        /// The hash value.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/>.
        /// </returns>
        bool Validate(string passwordString, string hashValue);

        #endregion
    }
}