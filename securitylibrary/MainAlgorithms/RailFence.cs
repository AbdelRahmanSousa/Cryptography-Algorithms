using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace SecurityLibrary
{
    public class Helper
    {
       private string PT;
       private string CT;
       private int k;
      public Helper(string p,string c) 
        {
          this.PT = p;
          this.CT = c;
        }
       public Helper(string p,int key,bool OP)
        {
            if(OP == false)
            {
                this.PT = p;
            }
            else { this.CT = p;}
            this.k = key;
        }
        public int getkey() { return this.k; }
        public string getPlaintext() { return this.PT; }
        public string getCiphertext() { return this.CT; }

        public List<int> AnalyseHelper()
        {
            List<int> keys_list = new List<int>();
            for (int i = 2; i < this.PT.Length; i++)
            {
                keys_list.Add(i);
            }
            return keys_list;
        }
        public string DecryptHelper(char[,] fence,int rows,int columns)
        {
            string plaintext = "";
            for (int i = 0; i < columns; i++)
            {
                int j = 0;
                while(j < rows)
                {
                    if (fence[j, i] != ' ')
                        plaintext += fence[j, i];
                    j++;
                }
            }
            return plaintext;
        }
        public string EncryptHepler(int key,List<String> list)
        {
            int i = 0;
            string output = "";
            while (i < key)
            {
                foreach (string text in list)
                {

                    if (text.Length <= i)
                        break;

                    output += text[i];

                }
                i++;
            }
            return output;
        }
        public bool AreTheyEqual()
        {
            return this.CT.Length % this.k == 0;
        }
       
    }
    public class RailFence : ICryptographicTechnique<string, int>
    {
        
        public int Analyse(string plainText, string cipherText)
        {
          int outputkey = 0;
          Helper Analyse_Helper = new Helper(plainText,cipherText);
          List<int> keys = Analyse_Helper.AnalyseHelper();
          foreach(int k in keys)
          {
               outputkey = Analyse_Helper.getCiphertext() == Encrypt(plainText, k)? k : outputkey;
               if(outputkey > 0) { return outputkey; }
          }
            return 0;
          

          
        }
        

         public string Decrypt(string cipher, int key)
         {
             Helper Decrypt_Helper = new Helper(cipher, key,true);
             int x2 = (int)(Math.Ceiling((double)cipher.Length/(double)key));
             int choosed_character = 0; 
             char[,] rail = new char[key, x2];

            if (Decrypt_Helper.AreTheyEqual())
            {
                for (int i = 0; i < key; i++)
                {
                    int j = 0;
                    while(j < x2)
                    {
                        rail[i, j] = cipher[choosed_character];
                        choosed_character++;
                        j++;
                    }
                }
            }
            else
            {
                int i = 0;
               while (i <key)
                {
                       
                    for (int j = 0; j < x2; j++)
                    {
                            rail[i, j] = (i != 0 && j == x2 - 1)? ' ':cipher[choosed_character];
                            choosed_character = (i != 0 && j == x2 - 1) ? choosed_character : choosed_character+=1;
                    }
                    i++;
                    
                }
            }
           return Decrypt_Helper.DecryptHelper(rail,key,x2);
   
         }
        

        public string Encrypt(string plainText, int key)
        {
            Helper Encrypt_Helper = new Helper(plainText, key, false);
            String s = "";
            List<string> list = new List<string>();
            int PlainLength = plainText.Length;
            for (int j = 0;j< PlainLength;j++)
            {
                bool exist = (j % key == 0 && j != 0);
                if (exist)
                {
                    list.Add(s);
                    s = "";
                    
                }
                s += plainText[j];
                if (j == plainText.Length-1)
                {
                    list.Add(s);
                }
                
            }
            return Encrypt_Helper.EncryptHepler(key,list).ToUpper();
        }
    }
}
