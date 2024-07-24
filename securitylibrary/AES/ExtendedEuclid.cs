using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int x = -1, y = -1;
            int gcd = ExtendedEuclidean(number, baseN, ref x, ref y); // ref for return the output 
            if (gcd != 1) // if gcd != 1 then there can't be multiplicative inverse 
                return -1;
            else
                return negativeModuleHandler(x, baseN); // ensure x is positive
        }

        private int ExtendedEuclidean(int a, int b, ref int X, ref int Y)
        {
            // initalize variables to memorize last two X, Y
            // Ex: x1 memorize X(i-2)
            int x_C, y_C, q, r;
            int x1 = 1, x2 = 0,
                y1 = 0, y2 = 1;

            while (true)
            {
                // Calculate the reminder of the new a,b values
                q = a / b;
                r = a % b;

                // simulate the recursive call
                a = b;
                b = r;

                // calculate current X, Y
                x_C = x1 - q * x2;
                y_C = y1 - q * y2;

                // update the previous 2 X, Y
                x1 = x2;
                x2 = x_C;
                y1 = y2;
                y2 = y_C;

                // breaking condition
                if (b == 0)
                    break;
            }

            X = x1;
            Y = x1;
            return a;
        }
        private int negativeModuleHandler(int n, int baseN)
        {
            int tmp = n % baseN + baseN;
            return tmp % baseN;
        }
    }
}
