using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using UnimerseLib.Interfaces;

namespace UnimerseLib.Cryptography
{
    /// <summary>
    /// Wraps Windows DPAPI for protecting secrets tied to the current user context.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class WindowsKeyProtector : IKeyProtector
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WindowsKeyProtector"/> class.
        /// </summary>
        public WindowsKeyProtector() { }

        /// <summary>
        /// Persists plaintext bytes using DPAPI scoped to the current user.
        /// </summary>
        public byte[] Protect(byte[] plainData)
        {
            return ProtectedData.Protect(plainData, optionalEntropy: null, DataProtectionScope.CurrentUser);
        }

        /// <summary>
        /// Reverses DPAPI protection previously applied by <see cref="Protect"/>.
        /// </summary>
        public byte[] Unprotect(byte[] protectedData)
        {
            return ProtectedData.Unprotect(protectedData, optionalEntropy: null, DataProtectionScope.CurrentUser);
        }
    }
}
