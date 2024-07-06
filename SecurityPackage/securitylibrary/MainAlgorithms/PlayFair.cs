using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public  string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            char[,] newmatrix = matrixinit(key);
            //  Console.WriteLine(cipherText);
            /*for(int i = 0;i<5;i++)
            {

                for(int j=0;j<5;j++)
                    Console.Write(newmatrix[i,j]);
                Console.WriteLine();
            }*/
            cipherText = cipherText.ToLower();
            // cipherText = cipherText.Replace(" ", "");
            //cipherText = cipherText.Replace("i", "j");
            string plainText = "";
            string plain_txt = "";
            /*for (int i = 0; i < cipherText.Length - 1; i += 2)
            {
                if (cipherText[i] == cipherText[i + 1])
                {
                    cipherText = cipherText.Insert(i + 1, "x");
                }
            }*/
            int frindex = 0;
            int fcindex = 0;
            int srindex = 0;
            int scindex = 0;
            for (int i = 0; i < cipherText.Length - 1; i += 2)
            {

                char fchar = cipherText[i];
                char schar = cipherText[i + 1];
                //Console.WriteLine(fchar);
                for (int j = 0; j < 5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if (newmatrix[j, k].Equals(fchar))
                        {
                            frindex = j;
                            fcindex = k;
                        }
                        if (newmatrix[j, k].Equals(schar))
                        {
                            srindex = j;
                            scindex = k;
                        }
                    }
                }

                if (fcindex == scindex)
                {
                    plainText += newmatrix[(frindex - 1 + 5) % 5, fcindex];
                    plainText += newmatrix[(srindex - 1 + 5) % 5, scindex];
                    // Commented
                    ///if (frindex == 4 && srindex != 4)
                    ///{
                    ///    cipher += newmatrix[0, fcindex];
                    ///    cipher += newmatrix[srindex + 1, scindex];
                    ///}
                    ///else if (frindex == 4 && srindex == 4)
                    ///{
                    ///    cipher += newmatrix[0, fcindex];
                    ///    cipher += newmatrix[0, scindex];
                    ///}
                    ///else if (srindex == 4 && frindex != 4)
                    ///{
                    ///    cipher += newmatrix[frindex + 1, fcindex];
                    ///    cipher += newmatrix[0, scindex];
                    ///}
                    ///else
                    ///{
                    ///    cipher += newmatrix[(frindex + 1), fcindex];
                    ///    cipher += newmatrix[(srindex + 1), scindex];
                    ///}
                }
                else if (frindex == srindex)
                {
                    plainText += newmatrix[frindex, (fcindex - 1 + 5) % 5];
                    plainText += newmatrix[srindex, (scindex - 1 + 5) % 5];

                    //Comment
                    ///    if (fcindex == 4 && scindex != 4)
                    ///    {
                    ///        cipher += newmatrix[frindex, 0];
                    ///        cipher += newmatrix[srindex, scindex + 1];
                    ///    }
                    ///    else if (fcindex == 4 && scindex == 4)
                    ///    {
                    ///        cipher += newmatrix[frindex, 0];
                    ///        cipher += newmatrix[srindex, 0];
                    ///    }
                    ///    else if (scindex == 4 && fcindex != 4)
                    ///    {
                    ///        cipher += newmatrix[frindex, fcindex + 1];
                    ///        cipher += newmatrix[srindex, 0];
                    ///}
                    ///else
                    ///{
                    ///    cipher += newmatrix[frindex, (fcindex + 1)];
                    ///    cipher += newmatrix[srindex, (scindex + 1)];
                    ///}

                }
                else
                {

                    plainText += newmatrix[frindex, scindex];
                    plainText += newmatrix[srindex, fcindex];
                }
            }

            //plainText = plainText.Replace("x", "");
            //Console.WriteLine(plainText);
           
            plain_txt += plainText[0];
            for(int i=1;i<plainText.Length-1;i++)
            {
                if (plainText[i] == 'x' && i % 2 != 0 && plainText[i - 1] == plainText[i+1])
                {
                    continue;
                }
                plain_txt += plainText[i];
            }
            if (plainText[plainText.Length - 1] != 'x')
            {
                plain_txt += plainText[plainText.Length-1];
            }
            //Console.WriteLine(plainText);
            return plain_txt;
        }

        public string Encrypt(string plainText, string key)
        {
            
            char[,] newmatrix = matrixinit(key);
            plainText = plainText.ToLower();
            plainText = plainText.Replace(" ", "");
            plainText = plainText.Replace("j", "i");
            int frindex = 0;
            int fcindex = 0;
            int srindex = 0;
            int scindex = 0;
            string cipher = "";
           
            for (int i=0;i<plainText.Length-1;i+=2)
            {
                if(plainText[i] == plainText[i+1])
                {
                    plainText= plainText.Insert(i+1, "x");
                }
            }
            if ((plainText.Length) % 2 != 0)
            {
                plainText += "x";
            }
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
               
                char fchar = plainText[i];
                char schar = plainText[i + 1];
                for (int j = 0; j < 5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if (newmatrix[j, k].Equals(fchar))
                        {
                            frindex = j;
                            fcindex = k;
                        }
                        if (newmatrix[j, k].Equals(schar))
                        {
                            srindex = j;
                            scindex = k;
                        }
                    }
                }
                
                if (fcindex == scindex)
                {

                    if (frindex == 4 && srindex !=4)
                    {
                        cipher += newmatrix[0, fcindex];
                        cipher += newmatrix[srindex + 1, scindex];
                    }

                    else if (frindex == 4 && srindex == 4)
                    {
                        cipher += newmatrix[0, fcindex];
                        cipher += newmatrix[0, scindex];
                    }
                    else if (srindex == 4 && frindex!=4)
                    {
                        cipher += newmatrix[frindex + 1, fcindex];
                        cipher += newmatrix[0, scindex];
                    }
                    else
                    {
                        cipher += newmatrix[(frindex + 1), fcindex];
                        cipher += newmatrix[(srindex + 1), scindex];
                    }
                }
                else if (frindex == srindex)
                {
                    if (fcindex == 4 && scindex!=4)
                    {
                        cipher += newmatrix[frindex, 0];
                        cipher += newmatrix[srindex, scindex + 1];
                    }
                    else if (fcindex == 4 && scindex == 4)
                    {
                        cipher += newmatrix[frindex, 0];
                        cipher += newmatrix[srindex, 0];
                    }

                    else if (scindex == 4 && fcindex != 4)
                    {
                        cipher += newmatrix[frindex, fcindex + 1];
                        cipher += newmatrix[srindex, 0];
                    }

                    else
                    {

                        cipher += newmatrix[frindex, (fcindex + 1)];
                        cipher += newmatrix[srindex, (scindex + 1)];
                    }

                }
                else
                {
                   
                    cipher += newmatrix[frindex, scindex];
                    cipher += newmatrix[srindex, fcindex];
                }
            }
            
             return cipher.ToUpper();
        }
        public char[,] matrixinit(string key)
        {
            char[,] newmat = new char[5, 5];
            string newkey1 = key.ToLower();
            newkey1= newkey1.Replace(" ", "");
            newkey1 = newkey1.Replace("j", "i");
            string newkey = new string(newkey1.Distinct().ToArray());
            int row = 0;
            int col = 0;
            string alpha = "abcdefghiklmnopqrstuvwxyz";
           
            for (int i=0;i<newkey.Length;i++)
            {
               
             
              
                    newmat[row, col] = newkey[i];
                    col++;
                    if (col == 5)
                    {
                        col = 0;
                        row++;
                            if (row==5)
                            {
                                break;
                            }
                    }
                
                    
               
               
            }
            for (int i = 0; i < alpha.Length; i++)
            {
              
               if(!key.Contains(alpha[i]))
               {   
              
                   
                        newmat[row, col] = alpha[i];
                        col++;
                        if (col == 5)
                        {
                            col = 0;
                            row++;
                            if (row==5)
                            {
                                break;
                            }
                        
                        }
                }

            }
            return newmat;
        }
    }
}