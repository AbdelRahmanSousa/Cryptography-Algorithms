using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            string The_cipher;
            string The_plain;
            The_plain = plainText.ToLower();
            The_cipher = cipherText.ToLower();
            int size = cipherText.Length;
            int res;
            for (int i = 0; i < size; i++)
            {
                res = The_cipher[i] - The_plain[i];
                if (res >= 0) // case positive
                {
                    key = key + (Convert.ToChar((res + 97)));

                }
                else // case negative -> 123 to wrap arround letters
                {
                    key = key + (Convert.ToChar((res + 123)));
                }

            }
            bool k = key.Contains(The_plain[0]);
            if (k)
            {
                int index = key.LastIndexOf(The_plain[0]);
                int stop = index;
                int count = 0;
                bool flag = true;
                count++;
                do
                {
                    index++;
                    if (!(key[index] == The_plain[count]))
                    {
                        flag = false;
                        break;
                    }
                    count++;
                } while (!(index >= key.Length - 1));

                if (flag != false)
                {
                    key = key.Remove(stop, key.Length - stop);
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string plain = "";
            string The_cipher;
            string The_Key;
            The_Key = key.ToLower();
            The_cipher = cipherText.ToLower();
            int res;
            int size = The_cipher.Length;
            for (int i = 0; i < size; i++)
            {
                res = The_cipher[i] - The_Key[i];
                if (res >= 0)
                {
                    plain += (Convert.ToChar((res + 97)));
                }
                else
                {
                    plain += (Convert.ToChar((res + 123)));
                }
                if (The_Key.Length >= The_cipher.Length)
                {
                    continue;
                }
                else
                {
                    The_Key = The_Key + plain[i];

                }

            }

            return plain;
        }


        public string Encrypt(string plainText, string key)
        {
            string cipher = "";
            string The_Plain;
            string The_Key;
            The_Key = key.ToLower();
            The_Plain = plainText.ToLower();
            int cut = The_Plain.Length - The_Key.Length;
            The_Key = The_Key + The_Plain.Substring(0, cut);

            int res;
            int size = The_Key.Length;
            for (int i = 0; i < size; i++)
            {
                res = The_Key[i] + The_Plain[i];
                if ((res - 97) <= 122)
                {
                    cipher = cipher + Convert.ToChar(res - 97);
                }
                else
                {
                    cipher = cipher + Convert.ToChar(res - 123);

                }

            }
            return cipher;


        }
    }
}
