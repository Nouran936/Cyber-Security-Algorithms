using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            string c_txt = cipherText.ToLower();
            string p_txt = plainText.ToLower();
            string letters = "abcdefghijklmnopqrstuvwxyz";
            string key = "";
            SortedDictionary<char, char> converted_table = new SortedDictionary<char, char>();
            for (int i = 0; i < c_txt.Length; i++)
            {
                if (converted_table.ContainsKey(p_txt[i]))
                {
                    continue;
                }
                else
                {
                    converted_table.Add(p_txt[i], c_txt[i]);
                }
            }
            if (converted_table.Count == 26)
            {
                foreach (KeyValuePair<char, char> pairs in converted_table)
                {
                    key += pairs.Value;
                }
            }
            else
            {
                for (int i = 0; i < letters.Length; i++)
                {
                    if (converted_table.ContainsKey(letters[i]))
                    {
                        continue;
                    }
                    else
                    {
                        for (int j = 0; j < letters.Length; j++)
                        {
                            if (converted_table.ContainsValue(letters[j]))
                            {
                                continue;
                            }
                            else
                            {
                                converted_table.Add(letters[i], letters[j]);
                                break;
                            }
                        }
                    }
                }
                foreach (KeyValuePair<char, char> pairs in converted_table)
                {
                    key += pairs.Value;
                }
            }
            return key;

        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            string c_txt = cipherText.ToLower();
            string p_key = key.ToLower();
            string letters = "abcdefghijklmnopqrstuvwxyz";
            string str = "";
            Dictionary<char, char> converted_table = new Dictionary<char, char>();
            for (int i = 0; i < 26; i++)
            {
                converted_table.Add(p_key[i], letters[i]);
            }
            for (int i = 0; i < c_txt.Length; i++)
            {
                str += converted_table[c_txt[i]];
            }
            return str;

        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string p_txt = plainText.ToLower();
            string p_key = key.ToLower();
            string letters = "abcdefghijklmnopqrstuvwxyz";
            string str = "";
            Dictionary<char, char> converted_table = new Dictionary<char, char>();
            for (int i = 0; i < 26; i++)
            {
                converted_table.Add(letters[i], p_key[i]);
            }
            for (int i = 0; i < p_txt.Length; i++)
            {
                str += converted_table[p_txt[i]];
            }
            return str.ToUpper();
        }







        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	=
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        /// 

        public string AnalyseUsingCharFrequency(string cipher)
        {

            //throw new NotImplementedException();
            string c_txt = cipher.ToLower();
            string freq_letters = "etaoinsrhldcumfpgwybvkxjqz";
            string most_freq_in_c = "";
            string plain_txt = "";
            Dictionary<char, int> c_letters_count = new Dictionary<char, int>();
            Dictionary<char, char> converted_letters = new Dictionary<char, char>();
            float[] arr = new float[26];
            int max = -1;
            for (int i = 0; i < c_txt.Length; i++)
            {
                if (c_letters_count.ContainsKey(c_txt[i]))
                {
                    c_letters_count[c_txt[i]]++;
                }
                else
                {
                    c_letters_count.Add(c_txt[i], 1);
                }
            }
            while (c_letters_count.Count > 0)
            {
                foreach (KeyValuePair<char, int> pairs in c_letters_count)
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
                char key_found = c_letters_count.FirstOrDefault(x => x.Value == max).Key;
                most_freq_in_c += key_found;
                c_letters_count.Remove(key_found);
                max = -1;
            }
            for (int j = 0; j < most_freq_in_c.Length; j++)
            {
                converted_letters.Add(most_freq_in_c[j], freq_letters[j]);
            }
            for (int k = 0; k < c_txt.Length; k++)
            {
                plain_txt += converted_letters[c_txt[k]];
            }
            return plain_txt;

        }
    }
}