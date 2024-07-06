using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.DiffieHellman
{


    public class DiffieHellman
    {

        public int power(int f, int s, int sf)
        {
            //throw new NotImplementedException();
            int key = 1;
            int i = 0;
            while (i < s)
            {
                key *= f;
                key %= sf;
                i++;
            }
            return key;
        }

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {

            //throw new NotImplementedException();
            List<int> outputs = new List<int>();

            int publicA = 0;
            publicA = power(alpha, xa, q);

            int publicB = 0;
            publicB = power(alpha, xb, q);


            int secreteA = 0;
            secreteA = power(publicB, xa, q);

            int secreteB = 0;
            secreteB = power(publicA, xb, q);

            outputs.Add(secreteA);
            outputs.Add(secreteB);

            return outputs;
        }
    }
}