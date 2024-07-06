using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> key = new List<int>();
            int k1=-1, k2=-1,k3 = -1,k4 = -1;
            
            for(int i=0; i<26;i++)
            {
              for(int j=0;j<26;j++)
              {
                    if(MyAnalysis(i,j,plainText,cipherText,true))
                    {
                        k1= i;
                        k2= j;
                    }
                    if (MyAnalysis(i, j, plainText, cipherText, false))
                    {
                        k3 = i;
                        k4 = j;
                    }
                }
            }

            if (k1 == -1 || k2 == -1 || k3 == -1 || k4 == -1)
                throw new InvalidAnlysisException();
            key.Add(k1);
            key.Add(k2);
            key.Add(k3);
            key.Add(k4);
            foreach(var mm in key)
                Console.WriteLine(mm);
            return key;
            //throw new NotImplementedException();
        }
        public string Analyse(string plainText, string cipherText)
        {
            List<int> p = new List<int>();
            p= text_to_int(plainText);
            List<int> c = new List<int>();
            c= text_to_int(cipherText);
            List<int> k = new List<int>();
            k = Analyse(p, c);
            return int_to_text(k);
           
        }
        
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> result = new List<int>();
            int[,] InverseKeyMatrix = new int[3, 3];
            int[,] InverseKeyMatrixTrans = new int[3, 3];
            //int[,] Cipher2d = new int[cipherText.Count/3, 3];

            int step_size,det;

            if (key.Count == 4)
                step_size = 2;
            else
                step_size = 3;

            #region DetAndInverse
            if (key.Count == 4)
                det = key[0] * key[3] - key[1] * key[2];
            else
            {
                det = key[0] * (key[4] * key[8] - key[5] * key[7])
                    - key[1] * (key[3] * key[8] - key[5] * key[6])
                    + key[2] * (key[3] * key[7] - key[4] * key[6]);

            }
            det = ((det % 26) + 26) % 26;
            Console.WriteLine(det);
            int inverse = InverseFinder(det);
            Console.WriteLine(inverse);
            #endregion

            if (step_size==3)
            {

                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        int pow = i + j;
                        if (pow % 2 == 0)
                            pow = 1;
                        else
                            pow = -1;

                        int detHere = getDet(key, i, j);
                        // InverseKeyMatrix[i,j]=((inverse*pow*detHere)%26);
                        int Eq = inverse * pow * detHere;
                        InverseKeyMatrix[i, j] = ((Eq % 26) + 26) % 26;

                    }
                }

                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        InverseKeyMatrixTrans[i, j] = InverseKeyMatrix[j, i];
                        Console.Write($"{InverseKeyMatrixTrans[i, j]} ");
                    }
                    Console.WriteLine();

                }

                for (int i = 0; i < cipherText.Count; i += 3)
                {
                    result.Add((cipherText[i] * InverseKeyMatrixTrans[0, 0]
                        + cipherText[i + 1] * InverseKeyMatrixTrans[0, 1]
                        + cipherText[i + 2] * InverseKeyMatrixTrans[0, 2]) % 26);

                    result.Add((cipherText[i] * InverseKeyMatrixTrans[1, 0]
                        + cipherText[i + 1] * InverseKeyMatrixTrans[1, 1]
                        + cipherText[i + 2] * InverseKeyMatrixTrans[1, 2]) % 26);

                    result.Add((cipherText[i] * InverseKeyMatrixTrans[2, 0]
                        + cipherText[i + 1] * InverseKeyMatrixTrans[2, 1]
                        + cipherText[i + 2] * InverseKeyMatrixTrans[2, 2]) % 26);
                } 
            }
            else
            {
                int idx = 3;

                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        int pow = i + j;
                        if (pow % 2 == 0)
                            pow = 1;
                        else
                            pow = -1;

                        //int detHere = getDet(key, i, j);
                        // InverseKeyMatrix[i,j]=((inverse*pow*detHere)%26);
                        int Eq = inverse *key[idx] *pow;
                        //Console.WriteLine($"{Eq} ");
                        InverseKeyMatrix[i, j] = ((Eq % 26) + 26) % 26;
                        idx--;
                    }
                }

                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j <2 ; j++)
                    {
                        InverseKeyMatrixTrans[i, j] = InverseKeyMatrix[j, i];
                        Console.Write($"{InverseKeyMatrixTrans[i, j]} ");
                    }
                    Console.WriteLine();

                }

                for (int i = 0; i < cipherText.Count; i += 2)
                {
                    result.Add((cipherText[i] * InverseKeyMatrixTrans[0, 0]
                        + cipherText[i + 1] * InverseKeyMatrixTrans[0, 1]
                        ) % 26);

                    result.Add((cipherText[i] * InverseKeyMatrixTrans[1, 0]
                        + cipherText[i + 1] * InverseKeyMatrixTrans[1, 1]
                        ) % 26);

                   
                }
            }
            foreach (var x in result)
                Console.Write($"{x} ");
            return result;           
            // throw new NotImplementedException();
        }
        public string Decrypt(string cipherText, string key)
        {
            List<int> c = new List<int>();
            c = text_to_int(cipherText);
            List<int> k = new List<int>();
            k = text_to_int(key);
            List<int> p = new List<int>();
            p = Decrypt(c, k);
            return int_to_text(p);
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //throw new NotImplementedException();
            List<int> result = new List<int>();

            int i = 0;
            int step_size = 0;
            int j = 0;
            if (key.Count == 4)
                step_size = 2;
            else
                step_size = 3;
            while (i < plainText.Count)
            {
                //Console.WriteLine(i);
                if (step_size==2)
                {
                    if (i % 2 == 0)
                    {
                        j = 0;
                        int x = plainText[i] * key[j] + plainText[i + 1] * key[j + 1];
                        x = x % 26;
                        result.Add(x);
                        //Console.WriteLine(x);
                    }
                    else
                    {
                        j = 2;
                        int y = plainText[i - 1] * key[j] + plainText[i] * key[j + 1];
                        y = y % 26;
                        result.Add(y);
                        //Console.WriteLine(y);
                    } 
                }

                else
                {
                    if (i % 3 == 0)
                    {
                        j = 0;
                        int x = plainText[i] * key[j] + plainText[i + 1] * key[j + 1]
                            +plainText[i+2]*key[j+2];
                        x = x % 26;
                        result.Add(x);
                        //Console.WriteLine(x);
                    }
                    else if(i%3==1)
                    {
                        j = 3;
                        int x = plainText[i-1] * key[j] + plainText[i] * key[j + 1]
                           + plainText[i + 1] * key[j + 2];
                        x = x % 26;
                        result.Add(x);
                    }
                    else
                    {
                        j = 6;
                        int x = plainText[i-2] * key[j] + plainText[i - 1] * key[j + 1]
                           + plainText[i ] * key[j + 2];
                        x = x % 26;
                        result.Add(x);
                       // result.Add(y);
                        //Console.WriteLine(y);
                    }
                }

                //j++;
                //j%=step_size;
                i++;
            }
            //foreach(var x in result)
            //    Console.WriteLine(x);
            return result;
        }
        public string Encrypt(string plainText, string key)
        {
            List<int> c = new List<int>();
            c = text_to_int(plainText);
            List<int> k = new List<int>();
            k = text_to_int(key);
            List<int> p = new List<int>();
            p = Encrypt(c, k);
            return int_to_text(p);
        }


        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            List<int> mykeys= new List<int>();
            int step_size, det;
            int[,] InverseKeyMatrix = new int[3, 3];
            int[,] InverseKeyMatrixTrans = new int[3, 3];
            step_size = 3;

           
                det = plain3[0] * (plain3[4] * plain3[8] - plain3[5] * plain3[7])
                    - plain3[1] * (plain3[3] * plain3[8] - plain3[5] * plain3[6])
                    + plain3[2] * (plain3[3] * plain3[7] - plain3[4] * plain3[6]);

            
            det = ((det % 26) + 26) % 26;
            Console.WriteLine(det);
            int inverse = InverseFinder(det);
            Console.WriteLine(inverse);

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    int pow = i + j;
                    if (pow % 2 == 0)
                        pow = 1;
                    else
                        pow = -1;

                    int detHere = getDet(plain3, i, j);
                    // InverseKeyMatrix[i,j]=((inverse*pow*detHere)%26);
                    int Eq = inverse * pow * detHere;
                    InverseKeyMatrix[i, j] = ((Eq % 26) + 26) % 26;

                }
            }
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    InverseKeyMatrixTrans[i, j] = InverseKeyMatrix[j, i];
                    Console.Write($"{InverseKeyMatrixTrans[i, j]} ");
                }
                Console.WriteLine();

            }

            ///for (int i = 0; i < cipher3.Count; i += 3)
            ///{
            ///    mykeys.Add((cipher3[i] * InverseKeyMatrixTrans[0, 0]
            ///        + cipher3[i + 1] * InverseKeyMatrixTrans[1, 0]
            ///        + cipher3[i + 2] * InverseKeyMatrixTrans[2, 0]) % 26);
            ///
            ///    mykeys.Add((cipher3[i] * InverseKeyMatrixTrans[0, 1]
            ///        + cipher3[i + 1] * InverseKeyMatrixTrans[1, 1]
            ///        + cipher3[i + 2] * InverseKeyMatrixTrans[2, 1]) % 26);
            ///
            ///    mykeys.Add((cipher3[i] * InverseKeyMatrixTrans[0, 2]
            ///        + cipher3[i + 1] * InverseKeyMatrixTrans[1, 2]
            ///        + cipher3[i + 2] * InverseKeyMatrixTrans[2, 2]) % 26);
            ///}
            ///

            for(int i=0; i < 3;i++)
            {
                int z = 0;
                //Pin Col from cipher4
                //Pin 3 Values
                int c1, c2, c3;
                c1 = cipher3[0 + i];//0 1 
                c2 = cipher3[3 + i];//3 4 
                c3 = cipher3[6 + i];//6 7
                for (int j=0;j<3;j++)
                {
                    int ans ;
                    ans= c1 * InverseKeyMatrixTrans[j, 0]+
                        c2*InverseKeyMatrixTrans[j,1]+
                        c3*InverseKeyMatrixTrans[j,2];
                    mykeys.Add(ans%26);
                }
            }
            foreach (var x in mykeys)
                Console.Write($"{x} ");
            return mykeys;
            //  throw new NotImplementedException();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            List<int> p = new List<int>();
            p = text_to_int(plain3);
            List<int> c = new List<int>();
            c = text_to_int(cipher3);
            List<int> k = new List<int>();
            k = Analyse3By3Key(p, c);
            return int_to_text(k);
        }

        public int InverseFinder(int determinant)
        {
            //List<int> result = new List<int>();
            //int result;
            int a1 = 1,a2=0,a3=26;
            int b1=0,b2=1,b3=determinant;
            int q ;
            int t1 ;
            int t2 ;
            int t3 ;
            while (true)
            {
                if(b3==0)
                {
                    throw new System.Exception() ;
                }
                else if(b3==1)
                {
                    return ((b2 % 26) + 26) % 26;
                }
                q = a3 / b3;
                t1 = a1 - (q * b1);
                t2 = a2 - (q * b2);
                t3 = a3 - (q * b3);
                a1 =b1; a2=b2; a3=b3;
                b1=t1; b2=t2; b3=t3;
                Console.WriteLine($"{t1} {t2} {t3}");

            }
            //return 0;
        }

        public int getDet(List<int> values,int x,int y)
        {
            int ans ;
            List<int> sub = new List<int>();
            int  myiteratoridx=0;
            int[,] arr = new int[3, 3];
            // Now we have 2d Array
            for(int i=0;i<3;i++)
            {
                for(int j=0;j<3;j++)
                {
                    arr[i, j] = values[myiteratoridx];
                    myiteratoridx++;
                }
            }

            // Construct Sub array
            for(int i=0;i<3;i++)
            {
                for(int j=0; j<3;j++)
                {
                    if(i!=x&&j!=y)
                        sub.Add(arr[i,j]);
                }
            }

            ans = (sub[0] * sub[3]) - (sub[1] * sub[2]);
            //ans %= 26;

            return ans;
        }

        public bool MyAnalysis(int x,int y, List<int> plain, List<int> cipher,bool type)
        {
            for(int i=0;i<plain.Count;i+=2)
            {
                int cc;
                if (type)
                    cc = cipher[i];
                else
                    cc = cipher[i+1];
                if ((plain[i] * x + plain[i + 1] * y) % 26 != cc)
                    return false;
            }

            return true;
        }

        public List<int> text_to_int(string text)
        {
            text = text.ToLower();
            List<int> ans = new List<int>();
            foreach (char a in text)
            {

                ans.Add(a - 'a');


            }

            return ans;

        }

        public string int_to_text(List<int> int_stream)
        {

            string ans = "";
            foreach (int val in int_stream)
            {

                ans += (char)(val + 'a');
            }




            return ans;
        }
    }
}

