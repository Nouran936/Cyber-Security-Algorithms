using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            string cipher_txt = cipherText.ToLower();
            string plain_txt = plainText.ToLower();
            char cipher_char1 = cipher_txt[1];
            int count = 0;
            int sub = 0;
            string dec_txt = "";
            string dec_txt_sub = "";
            for (int i = 0; i < plain_txt.Length; i++)
            {
                if(cipher_char1 == plain_txt[i])
                {
                    if(plain_txt[i] == plain_txt[i+1] && i < plain_txt.Length - 1)
                    {
                        count++;
                    }
                    else if(plain_txt[i] != plain_txt[i + 1] && i < plain_txt.Length - 1)
                    {
                        for (int j=i-count; j <= i; j++)
                        {
                            string decrypted_txt = Decrypt(cipher_txt, j);
                            for (int k = 0; k < decrypted_txt.Length; k++)
                            {
                                if (Char.IsLetter(decrypted_txt[k]))
                                {
                                    dec_txt += decrypted_txt[k];
                                }
                            }
                            if(dec_txt.Length > plain_txt.Length)
                            {
                                sub = dec_txt.Length - plain_txt.Length;
                                for (int l = 0; l < dec_txt.Length-sub; l++)
                                {
                                    dec_txt_sub += dec_txt[l];
                                }
                                if (dec_txt_sub == plain_txt)
                                {
                                    return j;
                                }
                            }
                            else
                            {
                                if (dec_txt == plain_txt)
                                {
                                    return j;
                                }
                            }
                            
                            dec_txt = "";
                        }
                    }
                }
            }
            return -1;
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            string cipher_txt = cipherText.ToLower();
            string plainText = "";
            int row_size = key;
            int column_size = 0;
            int row = 0;
            int col = 0;
            if (cipher_txt.Length % row_size == 0)
            {
                column_size = cipher_txt.Length / row_size;
            }
            else
            {
                column_size = (cipher_txt.Length / row_size) + 1;
            }
            char[,] cipher_matrix = new char[row_size, column_size];
            for (int i = 0; i < cipher_txt.Length; i++)
            {
                cipher_matrix[row, col] = cipher_txt[i];
                col++;
                if (col == column_size && row != row_size)
                {
                    col = 0;
                    row++;
                }
            }
            for (int i = 0; i < column_size; i++)
            {
                for (int j = 0; j < row_size; j++)
                {
                    plainText += cipher_matrix[j, i];
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            string plain_txt = plainText.ToLower();
            string cipherText = "";
            int row_size = key;
            int column_size = 0;
            int row = 0;
            int col = 0;
            if (plain_txt.Length % row_size == 0)
            {
                column_size = plain_txt.Length / row_size;
            }
            else
            {
                column_size = (plain_txt.Length / row_size) + 1;
            }
            char[,] plain_matrix = new char[row_size, column_size];
            for (int i = 0; i < plain_txt.Length; i++)
            {
                plain_matrix[row, col] = plain_txt[i];
                row++;
                if (row == row_size && col != column_size)
                {
                    row = 0;
                    col++;
                }
            }
            for (int i = 0; i < row_size; i++)
            {
                for (int j = 0; j < column_size; j++)
                {
                    if(Char.IsLetter(plain_matrix[i, j]))
                    {
                        cipherText += plain_matrix[i, j];
                    }
                }
            }
            return cipherText.ToUpper();
        }
    }
}
