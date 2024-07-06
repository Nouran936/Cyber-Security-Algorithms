using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            // throw new NotImplementedException();
            int r = pow(alpha, k, q);
            int t = (m * pow(y, k, q)) % q;
            List<long> ciphertext = new List<long> { r, t };
            return ciphertext;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            // throw new NotImplementedException();
            int k = pow(c1, x, q);
            int invK = MultiInverse(k, q);
            int m = (c2 * invK) % q;

            return m;
        }

        public int pow(int c1, int x, int q)
        {
            int result = 1;
            for (int i = 0; i < x; i++)
            {
                result = (result * c1) % q;
            }

            return result;
        }

        public int MultiInverse(int number, int N)
        {
            //throw new NotImplementedException();
            int A1 = 1;
            int A2 = 0;
            int A3 = N;

            int B1 = 0;
            int B2 = 1;
            int B3 = number;


            while (true)
            {
                if (B3 == 0)
                {
                    return -1;
                }
                else if (B3 == 1)
                {
                    if (B2 < 0)
                    {
                        return (B2 % N + N) % N;
                    }
                    else
                    {
                        return (B2 % N);
                    }
                }
                int Q = A3 / B3;
                int T1 = A1 - (Q * B1);
                int T2 = A2 - (Q * B2);
                int T3 = A3 - (Q * B3);

                A1 = B1;
                A2 = B2;
                A3 = B3;

                B1 = T1;
                B2 = T2;
                B3 = T3;

            }

        }
    }
}
