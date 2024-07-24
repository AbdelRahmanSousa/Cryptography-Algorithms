using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string alphabetic = "abcdefghijklmnopqrstuvwxyz";
            cipherText = cipherText.ToLower();
            StringBuilder not = new StringBuilder();
            StringBuilder key = new StringBuilder();

            foreach (char letter in alphabetic)
            {
                if (plainText.Contains(letter))
                {
                    int indx = plainText.IndexOf(letter);
                    key.Append(cipherText[indx]);
                }
                else
                {
                    key.Append(' ');
                }
            }

            foreach (char letter in alphabetic)
            {
                if (!cipherText.Contains(letter))
                {
                    not.Append(letter);
                }
            }

            int notIndex = 0;
            foreach (char letter in key.ToString())
            {
                if (letter == ' ')
                {
                    key[notIndex] = not[0];
                    not.Remove(0, 1);
                }
                notIndex++;
            }

            return key.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string alphabetic = "abcdefghijklmnopqrstuvwxyz";
            Dictionary<char, char> p = new Dictionary<char, char>();

            int index = 0;
            foreach (char letter in alphabetic)
            {
                p[key[index]] = letter;
                index++;
            }

            StringBuilder plainText = new StringBuilder();
            foreach (char letter in cipherText)
            {
                plainText.Append(p[letter]);
            }
            return plainText.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            string alphabetic = "abcdefghijklmnopqrstuvwxyz";
            Dictionary<char, char> p = new Dictionary<char, char>();

            int index = 0;
            foreach (char letter in alphabetic)
            {
                p[letter] = key[index];
                index++;
            }

            StringBuilder cipherText = new StringBuilder();
            foreach (char letter in plainText)
            {
                cipherText.Append(p[letter]);
            }
            return cipherText.ToString();
        }

        public string AnalyseUsingCharFrequency(string cipher)
        {
            string freqalpha = "etaoinsrhldcumfpgwybvkxjqz";
            Dictionary<char, char> my_char = new Dictionary<char, char>();
            Dictionary<char, int> frequency = new Dictionary<char, int>();

            foreach (char letter in cipher)
            {
                if (frequency.ContainsKey(letter))
                {
                    frequency[letter]++;
                }
                else
                {
                    frequency[letter] = 1;
                }
            }

            int freqIndx = 0;
            var orderedFrequency = frequency.OrderByDescending(pair => pair.Value).ToList();
            for (int i = 0; i < orderedFrequency.Count; i++)
            {
                KeyValuePair<char, int> my_alphabetic = orderedFrequency[i];
                my_char[my_alphabetic.Key] = freqalpha[freqIndx];
                freqIndx++;
            }

            StringBuilder plainText = new StringBuilder();

            foreach (char letter in cipher)
            {
                plainText.Append(my_char[letter]);
            }

            return plainText.ToString();
        }
    }
}