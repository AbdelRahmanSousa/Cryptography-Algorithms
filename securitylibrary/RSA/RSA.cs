using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        private int n = 0;
        private int[] output = new int[2];
        private int finalresult = 1;
        public void keygeneration(int p, int q, int e,bool decrypt = false)
        {
            this.n = p * q;
            int euler = (p - 1) * (q - 1);
            ExtendedEuclid extendedEuclid = new ExtendedEuclid();
            this.output[0] = this.n; //first output is n (used in both encryption and decryption)
            this.output[1] = (decrypt) ? extendedEuclid.GetMultiplicativeInverse(e, euler) : e; 
            //second output is d = (e^-1 mod euler) in case of decryption / e in case of encryption
            
        }
        public void Generate(int dividend,int message)
        {
            do { finalresult = (finalresult * message) % this.n; dividend--; } while (dividend > 0);
        }
        public int Encrypt(int p, int q, int M, int e)
        {
            keygeneration(p, q, e);

            //Encryption: M^e mod n
            Generate(this.output[1], M);
            return finalresult;
            
           
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            keygeneration(p, q, e,true);
            //Decryption: C^d mod n
           Generate(this.output[1], C);
            return finalresult;
            
        }
    }
}
