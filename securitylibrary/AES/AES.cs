using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Linq;
using System.Linq.Expressions;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        
       private readonly char[,] INV =
        {
               {'E','B','D','9'},
               {'9','E','B','D'},
               {'D','9','E','B'},
               {'B','D','9','E'}
        };

       private readonly char[,] field =
        {
            {'2','3','1','1'},
            {'1','2','3','1'},
            {'1','1','2','3'},
            {'3','1','1','2'},
        };
       private readonly int[,]Substitute_box = {
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}};

        private readonly int[,] Substitute_INVERS ={
    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}};


        private readonly List<string> keygeneration_matrix =new List<string>() { "01", "02", "04", "08", "10", "20", "40", "80", "1b", "36" };
                

        public string Binary(string hex)
        {
            string binary = "";
            foreach (char c in hex)
            {
                int value = Convert.ToInt32(c.ToString(), 16);
                binary += Convert.ToString(value, 2).PadLeft(4, '0');
            }
            return binary;
        }
        

        public int shiftof2(string s, int subtraction)
        {
            char n = s[0];
            s = (s + "0").Substring(1, 8);
            int number = Convert.ToInt32(s, 2);
            return n == '1' ? (number ^ subtraction) : number;


        }
        public string original(string[, ]Text)
        {
            string output = "0x";
            for (int i = 0; i < Text.GetLength(1); i++)
            {
                for (int j = 0; j < Text.GetLength(1); j++)
                {
                    output += Text[j, i];
                }
            }
            return output;
        }
        public string[,] Read(string Text)
        {
            string[,] plaintext = new string[4, 4];
            int plain_counter = 2;
            for (int j = 0; j < plaintext.GetLength(1); j++)
            {
                for (int i = 0; i < plaintext.GetLength(1); i++)
                {
                    plaintext[i, j] = Text.Substring(plain_counter, 2);
                    plain_counter += 2;
                    if (plain_counter == Text.Length) break;
                }
            }
            return plaintext;
        }
        //1-SubBytes
        public string[,] sub(string[,] plainText, int[,] BOX)
        {
            string[,] result = new string[4, 4];
            for (int i = 0; i < plainText.GetLength(1); i++)
            {
                for (int j = 0; j < plainText.GetLength(1); j++)
                {
                    result[i, j] = BOX[Convert.ToInt32(plainText[i, j][0].ToString(), 16), Convert.ToInt32(plainText[i, j][1].ToString(), 16)].ToString("X2");
                }
            }
            return result;
        }
        //2-ShiftRows
        public string[,] ShiftRows(string[,] Text,bool inverse = false)
        {
            int row_index = 1;
            string temp = "";
            for (int i = 0; i < row_index; i++)
            {
                if (!inverse)
                {
                    temp = Text[row_index, 0];
                    Text[row_index, 0] = Text[row_index, 1];
                    Text[row_index, 1] = Text[row_index, 2];
                    Text[row_index, 2] = Text[row_index, 3];
                    Text[row_index, 3] = temp;
                }
                else
                {
                    temp = Text[row_index, 3];
                    Text[row_index, 3] = Text[row_index, 2];
                    Text[row_index, 2] = Text[row_index, 1];
                    Text[row_index, 1] = Text[row_index, 0];
                    Text[row_index, 0] = temp;
                }
                if (i == row_index - 1) { i = -1; row_index++; }
                if(row_index == Text.GetLength(0)) { break; }
            }

            return Text;
        }
        //3-MixColumns
        public string[,] MixColumns(string[,] Text)
        {
            string[,] output = new string[4,4];
            int subtraction = 27;
            for (int i = 0; i < Text.GetLength(0); i++)
            {
                for (int j = 0; j < Text.GetLength(0); j++)
                {
                    int multiplication = 0;
                    for (int k = 0; k < Text.GetLength(0); k++)
                    {
                        string s = Binary(Text[k, i]);
                        int number = Convert.ToInt32(s, 2);
                        char n = s[0];
                        s += "0";
                        s = s.Substring(1, 8);
                        if (field[j, k] == '1')
                        {

                            multiplication ^= number;

                        }
                        if (field[j, k] == '2')
                        {

                            int number2 = Convert.ToInt32(s, 2);
                            if (n == '1')
                            {
                                number2 ^= subtraction;
                            }
                            multiplication ^= number2;
                        }

                        else if (field[j, k] == '3')
                        {
                            int number3 = Convert.ToInt32(s, 2);
                            if (n == '1')
                            {
                                number3 ^= subtraction;
                            }
                            multiplication ^= (number ^ number3);

                        }

                    }
                    output[j, i] = multiplication.ToString("X2");

                }


            }
            return output;
        }
        //Inverse Mix-Columns
        public string[,] InverseMixColumns(string[,] Text)
        {
            string[,] output = new string[4, 4];
            int subtraction = 27;
            for (int i = 0; i < Text.GetLength(0); i++)
            {
                for (int j = 0; j < Text.GetLength(0); j++)
                {
                    int multiplication = 0;
                    for (int k = 0; k < Text.GetLength(0); k++)
                    {
                        string s = Binary(Text[k, i]);
                        int number = Convert.ToInt32(s, 2);
                        int value = 0;

                        if (INV[j, k] == '9')
                        {
                            string first_shift = shiftof2(s, subtraction).ToString("X2"); // shift
                            string second_shift = shiftof2(Binary(first_shift), subtraction).ToString("X2"); //shift
                            int third_shift = shiftof2(Binary(second_shift), subtraction); //shift

                            value = (third_shift ^ number); //xor

                        }
                        else if (INV[j, k] == 'B')
                        {
                            string first_shift = shiftof2(s, subtraction).ToString("X2"); //shift
                            int second_shift = shiftof2(Binary(first_shift), subtraction); //shift
                            string first_add = (second_shift ^ number).ToString("X2"); //xor
                            int third_shift = shiftof2(Binary(first_add), subtraction); //shift
                            value = (third_shift ^ number); //xor
                        }
                        else if (INV[j, k] == 'D')
                        {
                            int first_shift = shiftof2(s, subtraction); //shift
                            string first_add = (first_shift ^ number).ToString("X2"); //xor
                            string second_shift = shiftof2(Binary(first_add), subtraction).ToString("X2"); //shift
                            int third_shift = shiftof2(Binary(second_shift), subtraction); //shift
                            value = (third_shift ^ number); //xor
                        }
                        else
                        {
                            int first_shift = shiftof2(s, subtraction); //shift 2
                            string first_add = (first_shift ^ number).ToString("X2"); //xor
                            int second_shift = shiftof2(Binary(first_add), subtraction);//shift 2
                            string second_add = (second_shift ^ number).ToString("X2"); //xor
                            value = shiftof2(Binary(second_add), subtraction);


                        }
                        multiplication ^= value;

                    }
                    output[j, i] = multiplication.ToString("X2");

                }


            }
            return output;

        }
        //4-AddRoundedKey
        public string[,] AddRoundedKey(string[,] Text, string[,] key)
        {
            string[,] result = new string[4, 4];
            for (int j = 0; j < Text.GetLength(1); j++)
            {
                for (int i = 0; i < Text.GetLength(1); i++)
                {
                    int text_value = Convert.ToInt32(Text[i,j],16);
                    int key_value = Convert.ToInt32(key[i, j],16);
                    string new_value = (text_value ^ key_value).ToString("X2");
                    result[i,j] = new_value;
                }
            }
            return result;
        }
        //Key-Generation
        public string[,] GenerateRoundKey(string[,]key,int key_index)
        {
            string[,] newkey = new string[4, 4];
            //first column
            for(int i = 0;i<key.GetLength(1);i++)
            {
                newkey[i,0] = key[i,3];
            }
            string temp = newkey[0,0];
            for(int i = 0;i< key.GetLength(1); i++)
            {
                newkey[i, 0] = (i == 3) ? temp : newkey[i+1,0];
            }
            for (int i = 0; i < key.GetLength(1); i++)
            {
                newkey[i, 0] = Substitute_box[Convert.ToInt32(newkey[i, 0][0].ToString(), 16), Convert.ToInt32(newkey[i, 0][1].ToString(), 16)].ToString("X2");
            }
            for (int i = 0; i<key.GetLength(1);i++)
            {
                newkey[i, 0] = (i == 0) ? (Convert.ToInt32(key[i, 0], 16) ^ Convert.ToInt32(newkey[i, 0], 16) ^ Convert.ToInt32(keygeneration_matrix[key_index], 16)).ToString("X2")
                                        : (Convert.ToInt32(key[i, 0], 16) ^ Convert.ToInt32(newkey[i, 0], 16) ^ Convert.ToInt32("00", 16)).ToString("X2");
                
            }
            
            //Rest
            for(int i = 1;i<key.GetLength(1);i++)
            {
                for(int j = 0; j<key.GetLength(1);j++)
                {
                    newkey[j, i] = (Convert.ToInt32(key[j, i], 16) ^ Convert.ToInt32(newkey[j, i-1], 16)).ToString("X2");
                }
            }


            return newkey;
        }

      
        public override string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            string[,] Matrix_ciphertext = Read(cipherText);
            string[,] Matrix_key = Read(key);
            List<string[,]> keys = new List<string[,]>();
            keys.Add(Matrix_key);
            for(int i = 0;i < 10;i++)
            {
                Matrix_key = keys[i];
                keys.Add(GenerateRoundKey(Matrix_key, i));
                
                
            }
            keys.Reverse();
            string[,] ciphertext = AddRoundedKey(Matrix_ciphertext, keys[0]);
            for(int i = 1;i < 10;i++)
            {
                ciphertext = ShiftRows(ciphertext,true);
                ciphertext = sub(ciphertext, Substitute_INVERS);
                Matrix_key = keys[i];
                ciphertext = AddRoundedKey(ciphertext, Matrix_key);
                ciphertext = InverseMixColumns(ciphertext);

            }
            ciphertext = ShiftRows(ciphertext,true);
            ciphertext = sub(ciphertext,Substitute_INVERS);
            Matrix_key = keys[10];
            ciphertext = AddRoundedKey(ciphertext, Matrix_key);

            return original(ciphertext);

        }

        public override string Encrypt(string plainText, string key)
        {
             string[,] Matrix_plaintext = Read(plainText);
             string[,] Matrix_key = Read(key);
            
            //Initial Round
             string[,] plaintext = AddRoundedKey(Matrix_plaintext, Matrix_key);
            //9 Main Rounds (Subbytes-shiftRows-MixColumns-AddRoundedKey)
            for (int i = 0;i < 9;i++)
            {
                plaintext = sub(plaintext, Substitute_box); //1
                plaintext = ShiftRows(plaintext); //2
                plaintext = MixColumns(plaintext); //3

                Matrix_key = GenerateRoundKey(Matrix_key,i);
     
                plaintext = AddRoundedKey(plaintext, Matrix_key); //4
            }
            //Final Round (Subbytes-shiftRows-AddRoundedKey)
            plaintext = sub(plaintext, Substitute_box);
            plaintext = ShiftRows(plaintext);
            Matrix_key = GenerateRoundKey(Matrix_key, 9);
            plaintext = AddRoundedKey(plaintext, Matrix_key);
   
          
            return original(plaintext);
        }
    }
}
