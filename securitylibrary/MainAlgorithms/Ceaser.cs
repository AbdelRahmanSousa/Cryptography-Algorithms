using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string cipherText = "";
            int i = 0;
            while (i < plainText.Length)
            {
                cipherText += Convert.ToChar(((Convert.ToInt16(plainText[i]) - 97 + key) % 26) + 65);
                i++;
            }

            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = "";
            cipherText = cipherText.ToLower();
            int i = 0;
            while (i < cipherText.Length)
            {
                plainText += Convert.ToChar(((Convert.ToInt16(cipherText[i]) + (26 - key) - 97) % 26) + 97);
                i++;
            }
            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            int i = 0;
            int k = 0;

            while (i < plainText.Length)
            {
                k = (Convert.ToInt16(cipherText[i]) - Convert.ToInt16(plainText[i]) + 32);
                if (k < 0)
                {
                    k = k + 26;
                }
                i++;
            }
            return k;
        }
    }
}
