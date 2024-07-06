using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            string alphabets = "abcdefghijklmnopqrstuvwxyz";
            string keystream = "";
            string key = "";
            Dictionary<char, int> alpha_dic = new Dictionary<char, int>();
            for (int i = 0; i < alphabets.Length; i++)
            {
                alpha_dic.Add(alphabets[i], i);
            }

            for (int i = 0; i < cipherText.Length; i++)
            {
                char cipherChar = cipherText[i];
                char plainChar = plainText[i];

                int cipherIndex = alpha_dic[cipherChar];
                int plainIndex = alpha_dic[plainChar];

                int keystrIndex = cipherIndex - plainIndex;
                if (keystrIndex < 0)
                {
                    keystrIndex += 26;
                }
                keystrIndex %= 26;

                char keyChar = alphabets[keystrIndex];
                keystream += keyChar;
            }

            for(int i = 0; i < keystream.Length; i++)
            {
                key += keystream[i];
                
                string PL = Decrypt(cipherText, key);
                if (PL == plainText)
                {
                    break;
                }
                else
                {
                    continue;
                }
                                          
            }

            return key.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            string alphabets = "abcdefghijklmnopqrstuvwxyz";
            int diff = 0;
            string keystream = "";
            string plainText = "";
            Dictionary<char, int> alpha_dic = new Dictionary<char, int>();
            for (int i = 0; i < alphabets.Length; i++)
            {
                alpha_dic.Add(alphabets[i], i);
            }


            if (cipherText.Length > key.Length)
            {
                while (cipherText.Length > keystream.Length)
                {
                    keystream += key;
                }

            }


            else if (cipherText.Length < key.Length)
            {
                diff = key.Length - cipherText.Length;
                for (int i = 0; i < diff; i++)
                {
                    keystream += key[i];
                }
            }
            else
            {
                keystream = key;
            }


            for (int i = 0; i < cipherText.Length; i++)
            {
                char cipherChar = cipherText[i];
                char keystrChar = keystream[i];

                int cipherIndex = alpha_dic[cipherChar];
                int keystrIndex = alpha_dic[keystrChar];

                int plainIndex = cipherIndex - keystrIndex;
                if(plainIndex < 0)
                {
                    plainIndex += 26;
                }
                plainIndex %= 26;

                char plainChar = alphabets[plainIndex];
                plainText += plainChar;

            }
            

            return plainText.ToLower();

        }

        public string Encrypt(string plainText, string key)
        {
            key = key.ToLower();
            plainText = plainText.ToLower();
            string alphabets = "abcdefghijklmnopqrstuvwxyz";
            int diff = 0;
            string keystream = "";
            string cipherText = "";
            Dictionary<char, int> alpha_dic = new Dictionary<char, int>();
            for (int i = 0; i < alphabets.Length; i++)
            {
                alpha_dic.Add(alphabets[i], i);
            }


            if (plainText.Length > key.Length)
            {
                while (plainText.Length > keystream.Length)
                {
                    keystream += key;
                }

            }


            else if (plainText.Length < key.Length)
            {
                diff = key.Length - plainText.Length;
                for(int i = 0; i < diff; i++)
                {
                    keystream += key[i];
                }
            }
            else
            {
                keystream = key;
            }
            

            for (int i = 0; i < plainText.Length; i++)
            {
                char plainChar = plainText[i];
                char keystrChar = keystream[i];

                int plainIndex = alpha_dic[plainChar];
                int keystrIndex = alpha_dic[keystrChar];

                int cipherIndex = (plainIndex + keystrIndex) % 26;
                char cipherChar = alphabets[cipherIndex];
                cipherText += cipherChar;

            }

            return cipherText.ToUpper();

        }
    }
}

