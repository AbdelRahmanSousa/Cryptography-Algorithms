using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    /// 
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            HashSet<int> keyres = new HashSet<int>();

            for (int i = 0; i < 2; i++)
                for (int j = 0; j < 26 && keyres.Count < 4; j++)
                    for (int k = 0; k < 26 && keyres.Count < 4; k++)
                    {
                        int condition1 = CalculateCondition(plainText[0], plainText[1], j, k);
                        int condition2 = CalculateCondition(plainText[2], plainText[3], j, k);

                        if (condition1 == cipherText[i] && condition2 == cipherText[i + 2])
                        {
                            keyres.Add(j);
                            keyres.Add(k);
                            break;
                        }

                    }

            if (!(keyres.Count < 4)) return keyres.ToList();
            else throw new InvalidAnlysisException();

        }
        private int CalculateCondition(int x, int y, int j, int k)
        {
            return (x * j + y * k) % 26;
        }
        static List<int> CharacterIndices(string str)
        {
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            List<int> indices = new List<int>();
            foreach (char c in str)
            {
                int index = alphabet.IndexOf(c);
                indices.Add(index);
            }
            return indices;
        }

        static string MapToAlphabetic(HashSet<int> indices)
        {
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            string result = "";
            foreach (int index in indices)
            {
                if (index >= 0 && index < alphabet.Length)
                {
                    result += alphabet[index];
                }
                else
                {
                    result += "_";
                }
            }
            return result;
        }

        public string Analyse(string plainText, string cipherText)
        {
            HashSet<int> keyres = new HashSet<int>();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            List<int> plainText1 = CharacterIndices(plainText);
            List<int> cipherText1 = CharacterIndices(cipherText);

            for (int i = 0; i < 2; i++)
                for (int j = 0; j < 26 && keyres.Count < 4; j++)
                    for (int k = 0; k < 26 && keyres.Count < 4; k++)
                    {
                        int condition1 = CalculateCondition(plainText1[0], plainText1[1], j, k);
                        int condition2 = CalculateCondition(plainText1[2], plainText1[3], j, k);

                        if (condition1 == cipherText1[i] && condition2 == cipherText1[i + 2])
                        {
                            keyres.Add(j);
                            keyres.Add(k);
                            break;
                        }

                    }
            string ans = MapToAlphabetic(keyres);

            if (!(ans.Length < 4)) return ans;
            else throw new InvalidAnlysisException();
        }


        private static int Det(int[,] inputMatrix, int modulus)
        {
            int size = inputMatrix.Length / inputMatrix.GetLength(1);
            if (size == 1) return inputMatrix[0, 0];
            int determinantResult = 0;
            int determinantSign = 1;

            foreach (int columnIndex in Enumerable.Range(0, size))
            {
                int[,] subMatrix = new int[size - 1, size - 1];
                foreach (int rowIndex in Enumerable.Range(1, size - 1))
                {
                    int subMatrixColumnIndex = 0;
                    foreach (int subColumnIndex in Enumerable.Range(0, size))
                        if (subColumnIndex != columnIndex)
                            subMatrix[rowIndex - 1, subMatrixColumnIndex++] = inputMatrix[rowIndex, subColumnIndex];
                }

                int term = determinantSign * inputMatrix[0, columnIndex] * Det(subMatrix, modulus);
                determinantResult = (determinantResult + term) % modulus;
                determinantSign = -determinantSign;
            }

            int finalResult = (determinantResult + modulus);
            finalResult %= modulus;
            return finalResult;
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int keyCount = key.Count;
            int factor = 0;
            while ((factor + 1) * (factor + 1) <= keyCount) factor++;

            int counter = 0;
            int[,] keyMatrix = new int[factor, factor];
            int[,] inverseMatrix = new int[factor, factor];
            for (int row = 0; row < factor; row++)
                for (int col = 0; col < factor; col++)
                    keyMatrix[row, col] = key[counter++];

            int n = keyMatrix.Length / keyMatrix.GetLength(1);
            int[,] adjMatrix = new int[n, n];
            int colIndex = 0;
            while (colIndex < n)
            {
                int rowIndex = 0;
                while (rowIndex < n)
                {
                    int sign;
                    if ((rowIndex + colIndex) % 2 == 0) sign = 1;
                    else sign = -1;
                    int[,] minorMatrix = new int[n - 1, n - 1];
                    int second = 0;
                    int k = 0;
                    while (k < n)
                    {
                        if (k != rowIndex)
                        {
                            int first = 0;
                            int l = 0;
                            while (l < n)
                            {
                                if (l != colIndex)
                                {
                                    minorMatrix[second, first] = keyMatrix[k, l];
                                    first++;
                                }
                                l++;
                            }
                            second++;
                        }
                        k++;
                    }
                    int detResult = Det(minorMatrix, 26);
                    int adjValue = sign * detResult;
                    adjMatrix[colIndex, rowIndex] = adjValue;
                    rowIndex++;
                }
                colIndex++;
            }

            int detInv = Enumerable.Range(1, 25).FirstOrDefault(i => (Det(keyMatrix, 26) * i) % 26 == 1);
            if (detInv == 0) throw new Exception();
            foreach (int i in Enumerable.Range(0, n))
                foreach (int j in Enumerable.Range(0, n))
                {
                    int multResult = adjMatrix[i, j] * detInv;
                    int mod26 = multResult % 26;
                    int add26 = mod26 + 26;
                    int adjustedResult = add26 % 26;
                    inverseMatrix[i, j] = adjustedResult;
                }

            int rowCount = 0;
            while ((rowCount + 1) * (rowCount + 1) <= inverseMatrix.Length)
                rowCount++;

            List<int> resultPlainText = new List<int>();
            List<int> factorlist = new List<int>();
            int index = 0;
            foreach (var cipherValue in cipherText)
            {
                int factorIndex = index % factor;
                factorlist.Add(cipherValue);
                index++;

                if (index % factor == 0)
                {
                    int rowIndex = 0;
                    do
                    {
                        colIndex = 0;
                        int sum = Enumerable.Range(0, factor)
                            .Sum(k => inverseMatrix[rowIndex, k] * factorlist[k]);

                        resultPlainText.Add(sum % 26);
                        rowIndex++;
                    } while (rowIndex < rowCount);

                    factorlist.Clear();
                }
            }
            return resultPlainText.ToList();
        }


        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToUpper().Replace(" ", "");
            key = key.ToUpper().Replace(" ", "");

            List<int> cipherValues = cipherText.Select(c => c - 'A').ToList();
            List<int> keyValues = key.Select(c => c - 'A').ToList();

            int keyCount = keyValues.Count;
            int factor = 0;
            while ((factor + 1) * (factor + 1) <= keyCount) factor++;

            int counter = 0;
            int[,] keyMatrix = new int[factor, factor];
            for (int row = 0; row < factor; row++)
                for (int col = 0; col < factor; col++)
                    keyMatrix[row, col] = keyValues[counter++];

            int n = keyMatrix.GetLength(0);
            int[,] adjMatrix = new int[n, n];
            int colIndex = 0;
            while (colIndex < n)
            {
                int rowIndex = 0;
                while (rowIndex < n)
                {
                    int sign = (rowIndex + colIndex) % 2 == 0 ? 1 : -1;
                    int[,] minorMatrix = new int[n - 1, n - 1];
                    int second = 0;
                    int k = 0;
                    while (k < n)
                    {
                        if (k != rowIndex)
                        {
                            int first = 0;
                            int l = 0;
                            while (l < n)
                            {
                                if (l != colIndex)
                                {
                                    minorMatrix[second, first] = keyMatrix[k, l];
                                    first++;
                                }
                                l++;
                            }
                            second++;
                        }
                        k++;
                    }
                    int detResult = Det(minorMatrix, 26);
                    int adjValue = sign * detResult;
                    adjMatrix[colIndex, rowIndex] = adjValue;
                    rowIndex++;
                }
                colIndex++;
            }

            int detInv = Enumerable.Range(1, 25).FirstOrDefault(i => (Det(keyMatrix, 26) * i) % 26 == 1);
            if (detInv == 0) throw new Exception();
            int[,] inverseMatrix = new int[n, n];
            foreach (int i in Enumerable.Range(0, n))
            {
                foreach (int j in Enumerable.Range(0, n))
                {
                    int multResult = adjMatrix[i, j] * detInv;
                    int mod26 = multResult % 26;
                    int add26 = mod26 + 26;
                    int adjustedResult = add26 % 26;
                    inverseMatrix[i, j] = adjustedResult;
                }
            }

            int rowCount = 0;
            while ((rowCount + 1) * (rowCount + 1) <= inverseMatrix.Length)
                rowCount++;

            List<int> resultPlainText = new List<int>();
            List<int> factorlist = new List<int>();
            int index = 0;
            foreach (var cipherValue in cipherValues)
            {
                int factorIndex = index % factor;
                factorlist.Add(cipherValue);
                index++;

                if (index % factor == 0)
                {
                    int rowIndex = 0;
                    do
                    {
                        colIndex = 0;
                        int sum = Enumerable.Range(0, factor)
                            .Sum(k => inverseMatrix[rowIndex, k] * factorlist[k]);

                        resultPlainText.Add(sum % 26);
                        rowIndex++;
                    } while (rowIndex < rowCount);

                    factorlist.Clear();
                }
            }

            string decryptedText = string.Join("", resultPlainText.Select(i => (char)(i + 'A')));
            return decryptedText;
        }
        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int keyElementCount = key.Count;
            int squareRootFactor = 0;
            while ((squareRootFactor + 1) * (squareRootFactor + 1) <= keyElementCount) squareRootFactor++;

            int counter = 0;
            List<List<int>> keyMatrix = Enumerable.Range(0, squareRootFactor)
                .Select(i => Enumerable.Range(0, squareRootFactor)
                    .Select(j => key[counter++])
                    .ToList())
                .ToList();


            int plainRowCount = plainText.Count / squareRootFactor;
            counter = 0;
            List<List<int>> plainMatrix = Enumerable.Range(0, plainRowCount)
                .Select(i => Enumerable.Range(0, squareRootFactor)
                    .Select(j => plainText[counter++])
                    .ToList())
                .ToList();


            List<int> resultMatrix = new List<int>();
            for (int iterationCount = 0; iterationCount < plainRowCount; iterationCount++)
            {
                List<int> currentRow = plainMatrix[iterationCount];
                List<int> result = keyMatrix.Select(keyRow => keyRow.Zip(currentRow, (a, b) => a * b).Sum() % 26).ToList();
                resultMatrix.AddRange(result);
            }

            return resultMatrix;
        }
        public string Encrypt(string plainText, string key)
        {
            List<int> plainList = plainText.Select(c => c - 'a').ToList();
            List<int> keyList = key.Select(c => c - 'a').ToList();

            List<int> encryptedList = Encrypt(plainList, keyList);

            StringBuilder sb = new StringBuilder();
            foreach (int encryptedChar in encryptedList)
            {
                sb.Append((char)(encryptedChar + 'a'));
            }

            return sb.ToString();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            List<int> keyResult = new List<int>();
            int iterationI = 0;

            while (iterationI < 3 && keyResult.Count < 9)
            {
                int iterationJ = 0;

                while (iterationJ < 26)
                {
                    int iterationK = 0;

                    while (iterationK < 26)
                    {
                        int iterationL = 0;

                        while (iterationL < 26)
                        {
                            int term1, term2, term3;

                            int tempTerm1 = (iterationJ * plain3[0]);
                            int tempTerm2 = (iterationK * plain3[1]);
                            int tempTerm3 = (iterationL * plain3[2]);
                            int sumTerms1 = tempTerm1 + tempTerm2 + tempTerm3;
                            term1 = sumTerms1 % 26;

                            int tempTerm4 = (iterationJ * plain3[3]);
                            int tempTerm5 = (iterationK * plain3[4]);
                            int tempTerm6 = (iterationL * plain3[5]);
                            int sumTerms2 = tempTerm4 + tempTerm5 + tempTerm6;
                            term2 = sumTerms2 % 26;

                            int tempTerm7 = (iterationJ * plain3[6]);
                            int tempTerm8 = (iterationK * plain3[7]);
                            int tempTerm9 = (iterationL * plain3[8]);
                            int sumTerms3 = tempTerm7 + tempTerm8 + tempTerm9;
                            term3 = sumTerms3 % 26;


                            bool condition =
                                term1 == cipher3[iterationI] &&
                                term2 == cipher3[iterationI + 3] &&
                                term3 == cipher3[iterationI + 6];

                            if (condition)
                            {
                                keyResult.AddRange(new[] { iterationJ, iterationK, iterationL });
                                break;
                            }

                            iterationL++;
                        }

                        if (keyResult.Count == 9) break;
                        iterationK++;
                    }

                    if (keyResult.Count == 9) break;
                    iterationJ++;
                }

                iterationI++;
            }
            return keyResult;
        }
        public string Analyse3By3Key(string plain3, string cipher3)
        {
            plain3 = plain3.ToUpper().Replace(" ", "");
            cipher3 = cipher3.ToUpper().Replace(" ", "");

            if (plain3.Length != 9 || cipher3.Length != 9)
                throw new InvalidAnlysisException();
            List<int> plainValues = plain3.Select(c => c - 'A').ToList();
            List<int> cipherValues = cipher3.Select(c => c - 'A').ToList();

            List<int> keyResult = new List<int>();
            int iterationI = 0;

            while (iterationI < 3 && keyResult.Count < 9)
            {
                int iterationJ = 0;

                while (iterationJ < 26)
                {
                    int iterationK = 0;

                    while (iterationK < 26)
                    {
                        int iterationL = 0;

                        while (iterationL < 26)
                        {
                            int term1, term2, term3;

                            int tempTerm1 = (iterationJ * plainValues[0]) % 26;
                            int tempTerm2 = (iterationK * plainValues[1]) % 26;
                            int tempTerm3 = (iterationL * plainValues[2]) % 26;
                            int sumTerms1 = (tempTerm1 + tempTerm2 + tempTerm3) % 26;
                            term1 = sumTerms1;

                            int tempTerm4 = (iterationJ * plainValues[3]) % 26;
                            int tempTerm5 = (iterationK * plainValues[4]) % 26;
                            int tempTerm6 = (iterationL * plainValues[5]) % 26;
                            int sumTerms2 = (tempTerm4 + tempTerm5 + tempTerm6) % 26;
                            term2 = sumTerms2;

                            int tempTerm7 = (iterationJ * plainValues[6]) % 26;
                            int tempTerm8 = (iterationK * plainValues[7]) % 26;
                            int tempTerm9 = (iterationL * plainValues[8]) % 26;
                            int sumTerms3 = (tempTerm7 + tempTerm8 + tempTerm9) % 26;
                            term3 = sumTerms3;

                            bool condition =
                                term1 == cipherValues[iterationI] &&
                                term2 == cipherValues[iterationI + 3] &&
                                term3 == cipherValues[iterationI + 6];

                            if (condition)
                            {
                                keyResult.AddRange(new[] { iterationJ, iterationK, iterationL });
                                break;
                            }

                            iterationL++;
                        }

                        if (keyResult.Count == 9) break;
                        iterationK++;
                    }

                    if (keyResult.Count == 9) break;
                    iterationJ++;
                }

                iterationI++;
            }

            string key = string.Join("", keyResult.Select(i => (char)(i + 'A')));
            return key;
        }
    }
}
