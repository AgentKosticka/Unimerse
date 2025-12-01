using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UnimerseLib.Interfaces
{
    /*
     * Interface for key protection (encryption/decryption) implementations.
     * This interface defines methods for protecting (encrypting) and unprotecting (decrypting) data.
     * Implementations of this interface should provide the actual logic for these operations.
     */
    public interface IKeyProtector
    {
        public byte[] Protect(byte[] plainData);
        public byte[] Unprotect(byte[] protectedData);
    }
}
