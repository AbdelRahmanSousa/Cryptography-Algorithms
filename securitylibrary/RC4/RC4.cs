using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        int[] s = new int[256];
        int[] t = new int[256];


        public void Swap(int[] array, int i, int j)
        {
            int temp = array[i];
            array[i] = array[j];
            array[j] = temp;
        }
        public string Char(string hex)
        {
            string chars = "";
            int i = 2;
            while (i < hex.Length)
            {
                chars += char.ConvertFromUtf32(Convert.ToInt32(hex[i].ToString() + hex[i + 1].ToString(), 16));
                i += 2;
            }
            return chars;
        }

        public string Hexa(string chars)
        {
            string hex = "0x";
            int i = 0;
            while (i < chars.Length)
            {
                hex += Convert.ToByte(chars[i]).ToString("x2");
                i++;
            }
            return hex;
        }

        public void Fill_T(string key)
        {
            int l = key.Length;
            int i = 0;
            while (i < 256)
            {
                s[i] = i;
                t[i] = key[i % l];
                i++;
            }
        }

        public void FirstPermutation()
        {
            int perm = 0;
            int i = 0;
            while (i < 255)
            {
                perm = (perm + s[i] + t[i]) % 256;
                Swap(s, i, perm);
                i++;
            }
        }

        public string Generate_key(string input)
        {
            int i = 0;
            int j = 0;
            int key = 0;
            char[] res = new char[input.Length];
            int m = 0;
            while (m < input.Length)
            {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;
                Swap(s, i, j);
                int t = (s[i] + s[j]) % 256;
                key = s[t];
                res[m] = (char)(input[m] ^ key);
                m++;
            }
            return new string(res);
        }

        public override string Decrypt(string cipherText, string key)
        {
            bool hexa = false;
            if (cipherText[0] == '0' && cipherText[1] == 'x')
            {
                cipherText = Char(cipherText);
                key = Char(key);
                hexa = true;
            }

            Fill_T(key);
            FirstPermutation();
            string plainText = Generate_key(cipherText);

            if (hexa == true)
            {
                plainText = Hexa(plainText);
            }
            return plainText;

        }

        public override string Encrypt(string plainText, string key)
        {
            bool hexa = false;
            if (plainText[0] == '0' && plainText[1] == 'x')
            {
                plainText = Char(plainText);
                key = Char(key);
                hexa = true;
            }

            Fill_T(key);
            FirstPermutation();
            string cipherText = Generate_key(plainText);

            if (hexa == true)
            {
                cipherText = Hexa(cipherText);
            }
            return cipherText;
        }
    }
}
