using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{

    public class DiffieHellman
    {
        private int PowerRecursive(int basee, int power, int mod, int result)
        {
            if (power == 0) return result % mod;
            else if (power % 2 == 0)
                //power is even
                return PowerRecursive((basee * basee) % mod, power / 2, mod, result);
            else
                //power is odd
                return PowerRecursive(basee, power - 1, mod, (result * basee) % mod);
        }

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            return Enumerable.Repeat(PowerRecursive(PowerRecursive(alpha, xa, q, 1), xb, q, 1), 2).ToList();
        }
    }
}