using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {

        public string Decrypt(string cipherText, List<string> key)
        {
            DES des = new DES();
            string s1 = des.Decrypt(cipherText, key[0]);
            string s2 = des.Encrypt(s1, key[0]);
            string s3 = des.Decrypt(s2, key[1]);
            return s3;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            if (key.Count < 2) throw new ArgumentException();
            DES encryptor = new DES();
            string ct = encryptor.Encrypt(plainText, key[0]);
            ct = encryptor.Decrypt(ct, key[1]);
            ct = encryptor.Encrypt(ct, key[0]);
            return ct;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
