using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {

            key = HexToBits(key);

            Dictionary<int, int> PC_1_table = new Dictionary<int, int>()
            {
                { 0, 57 }, { 1, 49 }, { 2, 41 }, { 3, 33 }, { 4, 25 }, { 5, 17 }, { 6, 9 },
                { 7, 1 }, { 8, 58 }, { 9, 50 }, { 10, 42 }, { 11, 34 }, { 12, 26 }, { 13, 18 },
                { 14, 10 }, { 15, 2 }, { 16, 59 }, { 17, 51 }, { 18, 43 }, { 19, 35 }, { 20, 27 },
                { 21, 19 }, { 22, 11 }, { 23, 3 }, { 24, 60 }, { 25, 52 }, { 26, 44 }, { 27, 36 },
                { 28, 63 }, { 29, 55 }, { 30, 47 }, { 31, 39 }, { 32, 31 }, { 33, 23 }, { 34, 15 },
                { 35, 7 }, { 36, 62 }, { 37, 54 }, { 38, 46 }, { 39, 38 }, { 40, 30 }, { 41, 22 },
                { 42, 14 }, { 43, 6 }, { 44, 61 }, { 45, 53 }, { 46, 45 }, { 47, 37 }, { 48, 29 },
                { 49, 21 }, { 50, 13 }, { 51, 5 }, { 52, 28 }, { 53, 20 }, { 54, 12 }, { 55, 4 }
            };

            string Key_after_permutation = "";
            int i = 0;
            while (i < PC_1_table.Count)
            {
                Key_after_permutation += key[PC_1_table[i] - 1];
                i++;
            }
            key = Key_after_permutation;


            //from 0 to 28
            string C0 = "";
            string D0 = "";
            int halfLength = key.Length / 2;
            i = 0;
            while (i < key.Length)
            {
                if (i < halfLength)
                    C0 += key[i];
                else
                    D0 += key[i];

                i++;
            }


            Dictionary<int, int> left_shifts = new Dictionary<int, int>()
            {
                { 0, 1 }, { 1, 1 }, { 2, 2 }, { 3, 2 },
                { 4, 2 }, { 5, 2 }, { 6, 2 }, { 7, 2 },
                { 8, 1 }, { 9, 2 }, { 10, 2 }, { 11, 2 },
                { 12, 2 }, { 13, 2 }, { 14, 2 }, { 15, 1 }
            };

            Dictionary<int, int> ip_2_table = new Dictionary<int, int>()
            {
                { 0, 14 }, { 1, 17 }, { 2, 11 }, { 3, 24 }, { 4, 1 }, { 5, 5 },
                { 6, 3 }, { 7, 28 }, { 8, 15 }, { 9, 6 }, { 10, 21 }, { 11, 10 },
                { 12, 23 }, { 13, 19 }, { 14, 12 }, { 15, 4 }, { 16, 26 }, { 17, 8 },
                { 18, 16 }, { 19, 7 }, { 20, 27 }, { 21, 20 }, { 22, 13 }, { 23, 2 },
                { 24, 41 }, { 25, 52 }, { 26, 31 }, { 27, 37 }, { 28, 47 }, { 29, 55 },
                { 30, 30 }, { 31, 40 }, { 32, 51 }, { 33, 45 }, { 34, 33 }, { 35, 48 },
                { 36, 44 }, { 37, 49 }, { 38, 39 }, { 39, 56 }, { 40, 34 }, { 41, 53 },
                { 42, 46 }, { 43, 42 }, { 44, 50 }, { 45, 36 }, { 46, 29 }, { 47, 32 }
            };


            List<string> keys = new List<string>();
            int r = 0;

            while (r < 16)
            {
                // reminaing + shifted
                string shiftedC0 = C0.Substring(left_shifts[r]) + C0.Substring(0, left_shifts[r]);
                string shiftedD0 = D0.Substring(left_shifts[r]) + D0.Substring(0, left_shifts[r]);
                C0 = shiftedC0;
                D0 = shiftedD0;
                string merged_key = shiftedC0 + shiftedD0;

                string last_perm_in_key = "";
                int x = 0;
                while (x < ip_2_table.Count)
                {
                    last_perm_in_key += merged_key[ip_2_table[x] - 1];
                    x++;
                }

                keys.Insert(0, last_perm_in_key); //Insertinggg at the beginning of the list to be reversed
                r++;
            }


            // cipher //removing first 2 bits (x0)
            ///////////////////////////////////////////////////

            cipherText = cipherText.ToUpper();
            cipherText = HexToBits(cipherText);
            String cipher = cipherText;



            Dictionary<int, int> ip_table = new Dictionary<int, int>()
            {
                {1, 58}, {2, 50}, {3, 42}, {4, 34}, {5, 26}, {6, 18}, {7, 10}, {8, 2},
                {9, 60}, {10, 52}, {11, 44}, {12, 36}, {13, 28}, {14, 20}, {15, 12}, {16, 4},
                {17, 62}, {18, 54}, {19, 46}, {20, 38}, {21, 30}, {22, 22}, {23, 14}, {24, 6},
                {25, 64}, {26, 56}, {27, 48}, {28, 40}, {29, 32}, {30, 24}, {31, 16}, {32, 8},
                {33, 57}, {34, 49}, {35, 41}, {36, 33}, {37, 25}, {38, 17}, {39, 9}, {40, 1},
                {41, 59}, {42, 51}, {43, 43}, {44, 35}, {45, 27}, {46, 19}, {47, 11}, {48, 3},
                {49, 61}, {50, 53}, {51, 45}, {52, 37}, {53, 29}, {54, 21}, {55, 13}, {56, 5},
                {57, 63}, {58, 55}, {59, 47}, {60, 39}, {61, 31}, {62, 23}, {63, 15}, {64, 7}
            };

            string new_cipher = "";
            int y = 1;
            while (y <= 64)
            {
                new_cipher += cipher[ip_table[y] - 1];
                y++;
            }
            cipher = new_cipher;


            string left = "";
            string right = "";

            for (i = 0; i < 32; i++)
            {
                left += cipher[i];
            }

            for (i = 32; i < 64; i++)
            {
                right += cipher[i];
            }
            Dictionary<int, int> E_BIT_SELECTION_TABLE = new Dictionary<int, int>()
            {
                {1, 32}, {2, 1}, {3, 2}, {4, 3}, {5, 4}, {6, 5}, {7, 4}, {8, 5},
                {9, 6}, {10, 7}, {11, 8}, {12, 9}, {13, 8}, {14, 9}, {15, 10}, {16, 11},
                {17, 12}, {18, 13}, {19, 12}, {20, 13}, {21, 14}, {22, 15}, {23, 16}, {24, 17},
                {25, 16}, {26, 17}, {27, 18}, {28, 19}, {29, 20}, {30, 21}, {31, 20}, {32, 21},
                {33, 22}, {34, 23}, {35, 24}, {36, 25}, {37, 24}, {38, 25}, {39, 26}, {40, 27},
                {41, 28}, {42, 29}, {43, 28}, {44, 29}, {45, 30}, {46, 31}, {47, 32}, {48, 1}
            };

            int f = 0;
            while (f < 16)
            {
                string expanded_right = "";
                int x = 1;
                while (x <= 48)
                {
                    expanded_right += right[E_BIT_SELECTION_TABLE[x] - 1];
                    x++;
                }

                // XOR
                string XOR_result = XOR(expanded_right, keys[f]);

                string newPlainText = SBoxExpand(XOR_result);

                Dictionary<int, int> P_Table = new Dictionary<int, int>()
                {
                    { 1, 16 }, { 2, 7 }, { 3, 20 }, { 4, 21 }, { 5, 29 }, { 6, 12 }, { 7, 28 }, { 8, 17 },
                    { 9, 1 }, { 10, 15 }, { 11, 23 }, { 12, 26 }, { 13, 5 }, { 14, 18 }, { 15, 31 }, { 16, 10 },
                    { 17, 2 }, { 18, 8 }, { 19, 24 }, { 20, 14 }, { 21, 32 }, { 22, 27 }, { 23, 3 }, { 24, 9 },
                    { 25, 19 }, { 26, 13 }, { 27, 30 }, { 28, 6 }, { 29, 22 }, { 30, 11 }, { 31, 4 }, { 32, 25 }
                };

                string plain_after_Sbox = "";
                int o = 1;
                while (o <= 32)
                {
                    plain_after_Sbox += newPlainText[P_Table[o] - 1];
                    o++;
                }

                // XOR
                string xor_after_Sbox = XOR(plain_after_Sbox, left);

                left = right;
                right = xor_after_Sbox;

                f++;
            }

            Dictionary<int, int> IP_inverse = new Dictionary<int, int>()
            {
                { 1, 40 }, { 2, 8 }, { 3, 48 }, { 4, 16 }, { 5, 56 }, { 6, 24 }, { 7, 64 }, { 8, 32 },
                { 9, 39 }, { 10, 7 }, { 11, 47 }, { 12, 15 }, { 13, 55 }, { 14, 23 }, { 15, 63 }, { 16, 31 },
                { 17, 38 }, { 18, 6 }, { 19, 46 }, { 20, 14 }, { 21, 54 }, { 22, 22 }, { 23, 62 }, { 24, 30 },
                { 25, 37 }, { 26, 5 }, { 27, 45 }, { 28, 13 }, { 29, 53 }, { 30, 21 }, { 31, 61 }, { 32, 29 },
                { 33, 36 }, { 34, 4 }, { 35, 44 }, { 36, 12 }, { 37, 52 }, { 38, 20 }, { 39, 60 }, { 40, 28 },
                { 41, 35 }, { 42, 3 }, { 43, 43 }, { 44, 11 }, { 45, 51 }, { 46, 19 }, { 47, 59 }, { 48, 27 },
                { 49, 34 }, { 50, 2 }, { 51, 42 }, { 52, 10 }, { 53, 50 }, { 54, 18 }, { 55, 58 }, { 56, 26 },
                { 57, 33 }, { 58, 1 }, { 59, 41 }, { 60, 9 }, { 61, 49 }, { 62, 17 }, { 63, 57 }, { 64, 25 }
            };

            string after_IP_inverse_table = right + left;

            string plain = "";
            int b = 1;
            while (b <= 64)
            {
                plain += after_IP_inverse_table[IP_inverse[b] - 1];
                b++;
            }
            after_IP_inverse_table = plain;
            //conversting binary to hexa
            return BitsToHex(after_IP_inverse_table);
        }


        private readonly short[] IP = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
        private readonly short[] shift = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
        private readonly short[] compressionPermutation = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
        private readonly short[,,] sbox =  {
                    {
                        { 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
                        { 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
                        { 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
                        { 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }
                    },
                    {
                        { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
                        { 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
                        { 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
                        { 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
                    },
                    {
                        { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
                        { 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
                        { 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
                        { 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }
                    },
                    {
                        { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
                        { 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
                        { 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
                        { 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }
                    },
                    {
                        { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
                        { 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
                        { 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
                        { 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }
                    },
                    {
                        { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
                        { 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
                        { 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
                        { 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }
                    },
                    {
                        { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                        { 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                        { 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                        { 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
                    },
                    {
                        { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
                        { 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
                        { 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
                        { 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
                    }
            };
        private readonly short[] FP = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };
        private readonly short[] expansion = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };
        private readonly short[] straighten = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };
        private readonly short[] keyp = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };

        private string HexToBits(string hexString)
        {
            if (string.IsNullOrEmpty(hexString))
            {
                return "";
            }
            hexString = hexString.Substring(2, hexString.Length - 2);
            return string.Join(string.Empty, hexString.ToUpper().Select(c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')));
        }
        private string BitsToHex(string bitString)
        {
            if (string.IsNullOrEmpty(bitString) || bitString.Length % 4 != 0)
            {
                throw new ArgumentException("Input string must be a multiple of 4 bits");
            }

            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < bitString.Length; i += 4)
            {
                string group = bitString.Substring(i, 4);
                hexString.Append(Convert.ToInt32(group, 2).ToString("X"));
            }
            return "0x" + hexString.ToString();
        }
        private string permute(string input, short[] permutation)
        {
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < permutation.Length; i++)
            {
                builder.Append(input[permutation[i] - 1]);
            }
            return builder.ToString();
        }
        private string XOR(string input, string key)
        {
            if (input.Length != key.Length) throw new ArgumentException("Key and Input must have the same length");
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < input.Length; i++)
            {
                if (input[i] == key[i]) result.Append('0');
                else result.Append('1');
            }
            return result.ToString();
        }
        private string shift_left(string input, int shift)
        {
            StringBuilder circular_shift = new StringBuilder();
            for (int i = 0; i < shift; i++) circular_shift.Append(input[i]);
            return input.Substring(shift) + circular_shift.ToString();
        }
        private string SBoxExpand(string xor_res)
        {
            StringBuilder sbox_res = new StringBuilder();
            for (int j = 0; j < 8; j++)
            {
                short row = Convert.ToInt16(xor_res[j * 6].ToString() + xor_res[j * 6 + 5].ToString(), 2);
                short col = Convert.ToInt16(xor_res[j * 6 + 1].ToString() + xor_res[j * 6 + 2].ToString() + xor_res[j * 6 + 3].ToString() + xor_res[j * 6 + 4].ToString(), 2);
                int val = sbox[j, row, col];
                sbox_res.Append(Convert.ToString(val, 2).PadLeft(4, '0'));
            }
            return sbox_res.ToString();
        }
        public override string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            key = permute(HexToBits(key), keyp);
            //Start Encrypting blocks
            plainText = HexToBits(plainText);
            int block_index = 0;
            //Process Plain text as 64 bit blocks.
            while (block_index < plainText.Length)
            {
                //Split key and extract block.
                string left_key = key.Substring(0, 28);
                string right_key = key.Substring(28);
                string block = plainText.Substring(block_index, 64);
                //Initial Permutation
                block = permute(block, IP);
                //Split block into left and right.
                string leftBlock = block.Substring(0, 32);
                string rightBlock = block.Substring(32, 32);
                //Perform 16 Rounds
                for (short i = 0; i < 16; i++)
                {
                    //Step 1: Key Transformation
                    left_key = shift_left(left_key, shift[i]);
                    right_key = shift_left(right_key, shift[i]);
                    string round_key = left_key + right_key;
                    round_key = permute(round_key, compressionPermutation);
                    //Step 2: D Expansion
                    string permutedRightBlock = permute(rightBlock, expansion);
                    //XOR right with key
                    string xor_res = XOR(permutedRightBlock, round_key);
                    //SBox Permutation
                    string sbox = SBoxExpand(xor_res);
                    //Straighten Permutation
                    sbox = permute(sbox, straighten);
                    //XOR left with key
                    leftBlock = XOR(leftBlock, sbox);
                    //Swap left and right
                    if (i != 15)
                    {
                        string temp = leftBlock;
                        leftBlock = rightBlock;
                        rightBlock = temp;
                    }
                }
                //Combine and perform Final Permutation
                block = leftBlock + rightBlock;
                block = permute(block, FP);
                cipherText += block;
                block_index += 64;
            }
            return BitsToHex(cipherText);
        }
    }
}
