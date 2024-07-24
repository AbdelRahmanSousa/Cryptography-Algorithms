using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
            string The_cipher = "";
            string The_key = "";
            string The_temp = "";
            The_cipher = cipherText.ToLower();
            string The_alphabet = "abcdefghijklmnopqrstuvwxyz";
            int i1 = 0;
            while (i1 < The_cipher.Length)
            {
                int cipher_idx = The_alphabet.IndexOf(The_cipher[i1]);
                int plain_idx = The_alphabet.IndexOf(plainText[i1]);
                The_key += The_alphabet[((cipher_idx - plain_idx) + 26) % 26];
                i1++;
            }
            The_temp += The_key[0];
            int i2 = 1;
            while (i2 < The_key.Length)
            {
                if (!The_cipher.Equals(Encrypt(plainText, The_temp)))
                {
                    The_temp += The_key[i2];

                }
                else
                {
                    return The_temp;
                }
                i2++;
            }

            return The_key;

        }

        public char DecryptHelper(char cipherChar, char keyChar)
        {
            if (char.IsLetter(cipherChar))
            {
                int cipherOffset, KeyOffset, cipherIndex, keyIndex;
                if (!char.IsUpper(cipherChar))
                {
                    cipherOffset = 'a';
                    cipherIndex = -cipherOffset + cipherChar;
                }
                else
                {
                    cipherOffset = 'A';
                    cipherIndex = -cipherOffset + cipherChar;

                }
                if (!char.IsUpper(keyChar))
                {
                    KeyOffset = 'a';
                    keyIndex = -KeyOffset + keyChar;
                }
                else
                {
                    KeyOffset = 'A';
                    keyIndex = -KeyOffset + keyChar;

                }

                int plainIndex = (((-keyIndex + cipherIndex) % 26) + 26) % 26;
                char plainChar = Convert.ToChar(cipherOffset + plainIndex);
                return plainChar;
            }
            else
            {
                return cipherChar;
            }
        }

        public string Decrypt(string cipherText, string key)
        {
            StringBuilder The_repeatedKey = new StringBuilder(cipherText.Length);
            int i1 = 0;
            while (i1 < cipherText.Length)
            {
                int idx = i1 % key.Length;
                char k_c = key[idx];
                The_repeatedKey.Append(k_c);
                i1++;
            }
            StringBuilder The_plain = new StringBuilder(cipherText.Length);
            int i2 = 0;
            while (i2 < cipherText.Length)
            {
                char The_cipher = cipherText[i2];
                char The_key = The_repeatedKey[i2];
                char plain = DecryptHelper(The_cipher, The_key);
                The_plain.Append(plain);
                i2++;
            }

            return The_plain.ToString();
        }
        public string Encrypt(string plainText, string key)
        {
            int The_temp = 0;
            string The_cipher = "";
            string The_alphabet = "abcdefghijklmnopqrstuvwxyz";
            while (key.Length != plainText.Length)
            {
                key += key[The_temp];
                The_temp++;
            }
            int i1 = 0;
            while (i1 < plainText.Length)
            {
                int cipherIndex = ((The_alphabet.IndexOf(plainText[i1]) + The_alphabet.IndexOf(key[i1])) % 26);
                The_cipher += The_alphabet[cipherIndex];
                i1++;
            }
            return The_cipher;
        }



    }
}

