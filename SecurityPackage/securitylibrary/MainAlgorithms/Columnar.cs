using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            List<int> key=new List<int>();
            char[,] cipher_matrix;
            int row_size = 0;
            int row = 0;
            int col = 0;
            bool check=false;
            int max = -1;
            Dictionary<int, int> count_dic = new Dictionary<int, int>();
            for(int i=0; i < cipherText.Length; i++)
            {
                if(i == cipherText.Length - 1)
                {
                    break;
                }
                
                char c1= cipherText[i];
                char c2= cipherText[i+1];
                for (int j=0; j < plainText.Length; j++)
                {
                    if (plainText[j] == c1)
                    {
                        int pos1 = j;
                        if(j == plainText.Length - 1)
                        {
                            for(int m=0; m < plainText.Length; m++)
                            {
                                if (plainText[m] == c2)
                                {
                                    check = true;
                                    int pos2 = m;
                                    int diff = (plainText.Length-pos1) + pos2;
                                    if (count_dic.ContainsKey(diff))
                                    {
                                        count_dic[diff]++;
                                    }
                                    else
                                    {
                                        count_dic.Add(diff, 1);
                                    }
                                    break;
                                }
                            }
                        }
                        else
                        {
                            for (int k = j + 1; k < plainText.Length; k++)
                            {
                                if (plainText[k] == c2)
                                {
                                    check = true;
                                    int pos2 = k;
                                    int diff = pos2 - pos1;
                                    if (count_dic.ContainsKey(diff))
                                    {
                                        count_dic[diff]++;
                                    }
                                    else
                                    {
                                        count_dic.Add(diff, 1);
                                    }
                                    break;
                                }
                                else if (k == plainText.Length - 1 && plainText[k] != c2)
                                {
                                    for (int n = 0; n < j; n++)
                                    {
                                        if (plainText[n] == c2)
                                        {
                                            check = true;
                                            int pos2 = n;
                                            int diff = (plainText.Length - pos1) + pos2;
                                            if (count_dic.ContainsKey(diff))
                                            {
                                                count_dic[diff]++;
                                            }
                                            else
                                            {
                                                count_dic.Add(diff, 1);
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        if (check)
                            break;
                    }
                }
            }
            foreach (KeyValuePair<int, int> pairs in count_dic)
            {
                if (pairs.Value > max)
                {
                    max = pairs.Value;
                }
                else
                {
                    continue;
                }
            }
            int max_count = count_dic.FirstOrDefault(x => x.Value == max).Key;

            int column_size = max_count;
            string positions_plain_text = "";
            string positions_cipher_text = "";
            string text_x = "";
            int cipher_pos_count = 0;
            int count_loop = 0;
            if (plainText.Length % column_size == 0)
            {
                row_size = plainText.Length / column_size;
            }
            else
            {
                row_size = (plainText.Length / column_size) + 1;
            }
            char[,] plain_matrix = new char[row_size, column_size];
            for (int i = 0; i < plainText.Length; i++)
            {
                plain_matrix[row, col] = plainText[i];
                col++;
                if (col == column_size && row != row_size)
                {
                    col = 0;
                    row++;
                }
            }
            if (row == row_size - 1 && col <= column_size - 1)
            {
                while (col != column_size)
                {
                    plain_matrix[row, col] = 'x';
                    col++;
                }
            }
            Dictionary<string, int> plain_postions = new Dictionary<string, int>();
            Dictionary<string, int> cipher_postions = new Dictionary<string, int>();
            for (int i= 0;i < column_size; i++)
            {
                positions_plain_text = "";
                for (int j = 0; j < row_size-1; j++)
                {
                    positions_plain_text += plain_matrix[j, i];
                }
                plain_postions.Add(positions_plain_text, i+1);
            }
            for(int k=0; k < cipherText.Length; k++)
            {
                if (count_loop == row_size - 1)
                {
                    cipher_pos_count++;
                    if (plain_postions.ContainsKey(positions_cipher_text))
                    {
                        cipher_postions.Add(positions_cipher_text, cipher_pos_count);
                        positions_cipher_text = "";
                        count_loop = 0;
                        if (k != cipherText.Length - 1)
                            k += 1;
                    }
                    else
                    {
                        char missing_char = cipherText[k-count_loop-1];
                        text_x += missing_char;
                        for(int l = 0; l <positions_cipher_text.Length-1; l++)
                        {
                            text_x += positions_cipher_text[l];
                        }
                        positions_cipher_text = "";
                        cipher_postions.Add(text_x, cipher_pos_count);
                        text_x = "";
                        count_loop = 0;
                    }
                }
                positions_cipher_text += cipherText[k];
                count_loop++;
            }
            if(positions_cipher_text.Length == row_size-1)
            {
                cipher_postions.Add(positions_cipher_text, cipher_pos_count+1);
            }
            if (positions_cipher_text.Length < row_size - 1 && cipher_postions.Count < plain_postions.Count)
            {
                int sub = (row_size - 1) - positions_cipher_text.Length;
                for(int i = 1; i <= sub; i++)
                {
                    char missing_char = cipherText[cipherText.Length - positions_cipher_text.Length - i];
                    text_x += missing_char;
                }
                for (int l = 0; l < positions_cipher_text.Length; l++)
                {
                    text_x += positions_cipher_text[l];
                }
                cipher_postions.Add(text_x, cipher_pos_count+1);
                text_x = "";
            }
            foreach (KeyValuePair<string, int> pairs in plain_postions)
            {
                if (cipher_postions.ContainsKey(pairs.Key))
                {
                    key.Add(cipher_postions[pairs.Key]);
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            string cipher_txt = cipherText.ToLower();
            string plain_txt = "";
            int column_size = key.Max();
            int row_size = 0;
            int row = 0;
            int col = 0;
            int count = 0;
            int col_loop = 0;
            int num_div = 0;
            int cipher_indx = 0;
            if (cipher_txt.Length % column_size == 0)
            {
                row_size = cipher_txt.Length / column_size;
            }
            else
            {
                int mod = cipher_txt.Length % column_size;
                num_div = (cipher_txt.Length-mod)+column_size;
                row_size = (cipher_txt.Length / column_size) + 1;
            }
            int sub= num_div-cipher_txt.Length;
            char[,] cipher_matrix = new char[row_size, column_size];
            char[,] plain_matrix = new char[row_size, column_size];
            Dictionary<int, int> columnar_key_dic = new Dictionary<int, int>();
            foreach (int num in key)
            {
                columnar_key_dic.Add(num, count);
                count++;
            }
            for (int i = 0; i < cipher_txt.Length; i++)
            {
                if (num_div == 0)
                {
                    cipher_matrix[row, col] = cipher_txt[i];
                    row++;
                    if (row == row_size && col != column_size)
                    {
                        row = 0;
                        col++;
                    }
                }
                else
                {
                    foreach(int num in key)
                    {
                        int indx = columnar_key_dic[num];
                        if (num <= column_size && num >= column_size - (sub - 1))
                        {
                            for(int j=0; j < row_size-1; j++)
                            {
                                cipher_matrix[row, col] = cipher_txt[cipher_indx];
                                row++;
                                cipher_indx++;
                            }
                            cipher_matrix[row_size - 1, indx] = 'x';
                            row = 0;
                            col++;
                        }
                        else
                        {
                            for (int j = 0; j < row_size; j++)
                            {
                                cipher_matrix[row, col] = cipher_txt[cipher_indx];
                                row++;
                                if (row == row_size && col != column_size)
                                {
                                    row = 0;
                                    col++;
                                }
                                cipher_indx++;
                                
                            }
                        }
                    }
                    break;   
                }
            }
            for (int i = 1; i <= column_size; i++)
            {
                int indx = columnar_key_dic[i];
                for (int j = 0; j < row_size; j++)
                {
                    plain_matrix[j, indx] = cipher_matrix[j, col_loop];
                }
                col_loop++;
            }
            for (int i = 0; i < row_size; i++)
            {
                for (int j = 0; j < column_size; j++)
                {
                    plain_txt += plain_matrix[i, j];
                }
            }
            return plain_txt;
        }
        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();
            string plain_txt = plainText.ToLower();
            int column_size = key.Max();
            int row_size = 0;
            int row = 0;
            int col = 0;
            int count = 0;
            string cipher_text = "";
            Dictionary<int, int> columnar_key_dic = new Dictionary<int, int>();
            if (plain_txt.Length % column_size == 0)
            {
                row_size = plain_txt.Length / column_size;
            }
            else
            {
                row_size = (plain_txt.Length / column_size)+1;
            }
            char[,] encrypted_matrix = new char[row_size, column_size];
            for(int i=0; i < plain_txt.Length; i++)
            {
                encrypted_matrix[row, col] = plain_txt[i];
                col++;
                if(col== column_size && row !=row_size)
                {
                    col = 0;
                    row++;
                }
            }
            if(row == row_size-1 && col <= column_size-1)
            {
                while (col != column_size)
                {
                    encrypted_matrix[row, col] = 'x';
                    col++;
                }
            }
            foreach(int num in key)
            {
                columnar_key_dic.Add(num, count);
                count++;
            }
            for(int i=1;i<= column_size; i++)
            {
                int indx = columnar_key_dic[i];
                for (int j = 0; j < row_size; j++)
                {
                    cipher_text += encrypted_matrix[j, indx];
                }
            }
            return cipher_text.ToUpper();
        }
    }
}
