using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        public string Encrypt(string plainText, int key)
        {
            string cipher_text = "";
            string plain_text = plainText.ToLower();
            string all_Letters = "abcdefghijklmnopqrstuvwxyz";
            Dictionary<char, int> all_letters_DIC = new Dictionary<char, int>();
            for (int i = 0; i < all_Letters.Length; i++)
            {
                all_letters_DIC.Add(all_Letters[i],i);
            }
            for (int j = 0; j < plain_text.Length; j++)
            {
                int letter_index = all_letters_DIC[plain_text[j]];
                int equ = (letter_index + key) % 26;
                char letter_dic = all_letters_DIC.FirstOrDefault(x => x.Value == equ).Key;
                cipher_text += letter_dic;
            }
            return cipher_text.ToUpper();

        }

        public string Decrypt(string cipherText, int key)
        {
            string cipher_text = cipherText.ToLower();
            string plain_text = "";
            string all_Letters = "abcdefghijklmnopqrstuvwxyz";
            int equ = 0;
            Dictionary<char, int> all_letters_DIC = new Dictionary<char, int>();
            for (int i = 0; i < all_Letters.Length; i++)
            {
                all_letters_DIC.Add(all_Letters[i], i);
            }
            for (int j = 0; j < cipher_text.Length; j++)
            {
                int letter_index = all_letters_DIC[cipher_text[j]];
                if((letter_index - key) < 0)
                {
                    equ = ((letter_index - key)+26) % 26;
                }
                else
                {
                    equ = (letter_index - key) % 26;
                }
                char letter_dic = all_letters_DIC.FirstOrDefault(x => x.Value == equ).Key;
                plain_text += letter_dic;
            }
            return plain_text.ToLower();
        }

        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            string plain_text = plainText.ToLower();
            string cipher_text = cipherText.ToLower();
            for (int key = 0; key < 26; key++)
            {
                
                string decrypted_text = Decrypt(cipher_text, key);
                if (decrypted_text == plain_text)
                {
                    return key;
                }

            }
            return -1;
        }
    }
}