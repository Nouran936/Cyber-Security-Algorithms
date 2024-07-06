using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            //throw new NotImplementedException();
            int n = p * q;

            int C = M;
            for (int i = 1; i < e; i++)
            {
                C = (C * M) % n;

            }

            C %= n;
            return C;

        }

        public int Decrypt(int p, int q, int C, int e)
        {
            //throw new NotImplementedException();
            int D = 0;
            int n = p * q;
            int euler = (q - 1) * (p - 1);

            D = MultiInverse(e, euler) % euler;


            int M = C;
            for (int i = 1; i < D; i++)
            {
                M = (C * M) % n;
            }

            return M;
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
