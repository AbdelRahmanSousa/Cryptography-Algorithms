using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            char[,] matrix = createMatrix(key);
            printMatrix(matrix);
            string output = "";
            for (int i = 0; i < Math.Ceiling((float)(cipherText.Length / 2)); i++)
            {
                //Console.WriteLine("decrypt " + cipherText[i * 2] + cipherText[i * 2 + 1] + " to " + twinDecrption(matrix, cipherText[i * 2], cipherText[i * 2 + 1]));
                output = output + twinDecrption(matrix, cipherText[i * 2], cipherText[i * 2 + 1]);
            }
            if (output[output.Length - 1] == 'x') { output = output.Substring(0, output.Length - 1); }
            output = postProcessing(output);
            Console.WriteLine(output);
            return output;
        }

        public string Encrypt(string plainText, string key)
        {
            string output = "";
            char[,] matrix = createMatrix(key);
            plainText = plaintextPreprocessing(plainText);
            //printMatrix(matrix);
            if (plainText.Length % 2 == 1) { plainText = plainText + "x"; }
            //Console.WriteLine(plainText);
            for (int i = 0; i < Math.Ceiling((float)(plainText.Length / 2)); i++)
            {
                // Console.WriteLine("encrypt "+ plainText[i*2]+ plainText[i*2+1]+ " to " + twinEncrption(matrix, plainText[i * 2], plainText[i*2+1]));
                output = output + twinEncrption(matrix, plainText[i * 2], plainText[i * 2 + 1]);
            }
            //Console.WriteLine(output);
            return output;
        }

        //support function
        private char[,] createMatrix(string key)
        {

            // variables
            string alphabet = "abcdefghiklmnopqrstuvwxyz";
            key = key.ToLower();
            key = key.Replace("j", "i");
            char[,] matrix = new char[5, 5];

            HashSet<char> used = new HashSet<char>();

            // create the processed key to create the matrix
            StringBuilder processedKey = new StringBuilder();
            for (int i = 0; i < key.Length; i++)
            {
                if (!used.Contains(key[i]))
                {
                    used.Add(key[i]);
                    processedKey.Append(key[i]);
                }
            }

            for (int i = 0; i < 25; i++)
            {
                if (!used.Contains(alphabet[i]))
                {
                    processedKey.Append(alphabet[i]);
                }
            }

            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    matrix[i, j] = processedKey[i * 5 + j];
                }
            }

            return matrix;
        }
        private void printMatrix(char[,] matrix)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    Console.Write(matrix[i, j] + " ");
                }
                Console.WriteLine();
            }
        }
        private string twinEncrption(char[,] matrix, char a, char b)
        {
            int[] posa = new int[2];
            int[] posb = new int[2];
            findIndex(matrix, a, posa);
            findIndex(matrix, b, posb);

            if (posa[0] == posb[0])
            {
                return matrix[posa[0], (posa[1] + 1) % 5] + matrix[posb[0], (posb[1] + 1) % 5].ToString();
            }
            else if (posa[1] == posb[1])
            {
                return matrix[(posa[0] + 1) % 5, posa[1]] + matrix[(posb[0] + 1) % 5, posb[1]].ToString();
            }
            else
            {
                return matrix[posa[0], posb[1]] + matrix[posb[0], posa[1]].ToString();
            }

        }
        private string twinDecrption(char[,] matrix, char a, char b)
        {
            int[] posa = new int[2];
            int[] posb = new int[2];
            findIndex(matrix, a, posa);
            findIndex(matrix, b, posb);
            if (posa[0] == posb[0])
            {
                return matrix[posa[0], mod(posa[1] - 1, 5)] + matrix[posb[0], mod(posb[1] - 1, 5)].ToString();
            }
            else if (posa[1] == posb[1])
            {
                return matrix[mod(posa[0] - 1, 5), posa[1]] + matrix[mod(posb[0] - 1, 5), posb[1]].ToString();
            }
            else
            {
                return matrix[posa[0], posb[1]] + matrix[posb[0], posa[1]].ToString();
            }

        }
        private void findIndex(char[,] matrix, char a, int[] pos)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (matrix[i, j] == a)
                    {
                        pos[0] = i;
                        pos[1] = j;
                        return;
                    }
                }
            }
        }
        private string plaintextPreprocessing(string plaintext)
        {
            // checks every pair of characters that can be created, if there is a duplicate letter in a pair split it
            string preprocessed = "";
            int i = 0;
            while (i < plaintext.Length - 1)
            {
                if (plaintext[i] != plaintext[i + 1])
                {
                    preprocessed += plaintext[i].ToString() + plaintext[i + 1].ToString();
                    i += 2;
                }
                else
                {
                    preprocessed += plaintext[i] + "x";
                    i += 1;
                }
            }
            //Console.WriteLine(b);
            if (i < plaintext.Length) { return preprocessed + plaintext[plaintext.Length - 1].ToString(); } // because we can skip the final character
            return preprocessed;
        }

        private int mod(int x, int m)
        {
            //there is a problem with Modulus
            return (x % m + m) % m;
        }
        private string postProcessing(string text)
        {

            string noduplicatestring = text.Substring(0, 1);
            int i = 1;
            while(i < text.Length-1)
            {
              
             noduplicatestring = !(i % 2 != 0 && text[i] == 'x' && text[i + 1] == text[i - 1]) ? 
                                  noduplicatestring += text.Substring(i, 1) : noduplicatestring;
              i++;
            }
           return noduplicatestring = text[text.Length - 1] != 'x' ? (noduplicatestring += text[text.Length - 1]) : noduplicatestring;

            
        }
    }
}