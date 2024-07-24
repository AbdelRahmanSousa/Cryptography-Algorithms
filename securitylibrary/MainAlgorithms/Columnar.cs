using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Remoting;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        private List<char> extract_column(char[] text, int keyLength, int column_index)
        {
            if (column_index >= keyLength) return null;
            List<char> segment = new List<char>();
            for (int i = column_index; i < text.Length; i += keyLength)
            {
                segment.Add(text[i]);
            }
            return segment;
        }
        private string extract_column(string text, int keyLength, int column_index)
        {
            if (column_index >= keyLength) return null;
            string segment = string.Empty;
            for (int i = column_index; i < text.Length; i += keyLength)
            {
                segment += text[i];
            }
            return segment;
        }
        private bool are_arrays_equal(char[] arr1, char[] arr2)
        {
            bool are_equal = false;
            for (int j = 0; j < arr2.Length; j++)
            {
                if (arr1[j].ToString().ToUpper() != arr2[j].ToString().ToUpper())
                {

                    are_equal = false;
                    break;

                }
                else
                {
                    are_equal = true;
                }
            }
            return are_equal;
        }
        private List<int> NormalizeRanks(List<int> data)
        {
            if (data.Count <= 1)
            {
                return data;
            }
            List<int> sortedData = new List<int>(data);
            sortedData.Sort();
            Dictionary<int, int> valueToRank = new Dictionary<int, int>();
            for (int i = 0; i < sortedData.Count; i++)
            {
                valueToRank.Add(sortedData[i], i);
            }

            // Apply the rank mapping to the original data
            List<int> normalizedRanks = new List<int>(data.Count);
            foreach (int value in data)
            {
                normalizedRanks.Add(valueToRank[value] + 1);
            }
            return normalizedRanks;
        }
        public List<int> Analyse(string plainText, string cipherText)
        {
            if (plainText == cipherText) return new List<int> { 1 };
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            List<int> key = null;
            for (int kl = 2; kl <= plainText.Length; kl++)
            {
                List<int> potential_key = new List<int>();
                for (int column = 0; column < kl; column++)
                {
                    string extractedColumn = extract_column(plainText, kl, column);
                    int index = cipherText.IndexOf(extractedColumn);
                    if (index == -1)
                    {
                        break;
                    }
                    else { potential_key.Add(index); }
                }
                if (potential_key.Count == kl)
                {
                    key = potential_key;
                    break;
                }
            }
            key = NormalizeRanks(key);
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int nRows = (int)Math.Ceiling(Convert.ToDouble(cipherText.Length) / Convert.ToDouble(key.Count));
            char[] chars = cipherText.ToCharArray();
            string plainText = "";
            for (int i = 0; i < nRows; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    int index = (key[j] - 1) * nRows + i;
                    string current = "X";
                    if (index < chars.Length)
                    {
                        current = chars[index].ToString();
                    }
                    plainText += current;
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            double nRows = Math.Ceiling(Convert.ToDouble(plainText.Length) / Convert.ToDouble(key.Count));
            char[] chars = plainText.ToCharArray();
            string[] cipherText = new string[key.Count];
            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < nRows; j++)
                {
                    string current = string.Empty;
                    if (cipherText[key[i] - 1] == null)
                    {
                        current = "X";
                    }
                    int index = j * key.Count + i;
                    if (index < chars.Length)
                    {
                        current = chars[index].ToString();
                    }
                    cipherText[key[i] - 1] += current;
                }
            }
            return cipherText.Aggregate("", (x, y) => { return x + y; });
        }
    }
}
