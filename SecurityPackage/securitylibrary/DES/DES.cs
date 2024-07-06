using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            string[] all_keys = KeyExpansion(key);
            string bin_cipher_txt = FromHexToBin(cipherText);
            string cipher_ip = CipherTxtAfterIP(bin_cipher_txt);
            string[] splitted_cipher = SplitKey(cipher_ip);
            string l16 = splitted_cipher[0];
            string r16 = splitted_cipher[1];
            string l15 = r16;
            string r15 = XORKeyWithE(l16, FunRandK(r16, all_keys, 16));
            string l14 = r15;
            string r14 = XORKeyWithE(l15, FunRandK(r15, all_keys, 15));
            string l13 = r14;
            string r13 = XORKeyWithE(l14, FunRandK(r14, all_keys, 14));
            string l12 = r13;
            string r12 = XORKeyWithE(l13, FunRandK(r13, all_keys, 13));
            string l11 = r12;
            string r11 = XORKeyWithE(l12, FunRandK(r12, all_keys, 12));
            string l10 = r11;
            string r10 = XORKeyWithE(l11, FunRandK(r11, all_keys, 11));
            string l9 = r10;
            string r9 = XORKeyWithE(l10, FunRandK(r10, all_keys, 10));
            string l8 = r9;
            string r8 = XORKeyWithE(l9, FunRandK(r9, all_keys, 9));
            string l7 = r8;
            string r7 = XORKeyWithE(l8, FunRandK(r8, all_keys, 8));
            string l6 = r7;
            string r6 = XORKeyWithE(l7, FunRandK(r7, all_keys, 7));
            string l5 = r6;
            string r5 = XORKeyWithE(l6, FunRandK(r6, all_keys, 6));
            string l4 = r5;
            string r4 = XORKeyWithE(l5, FunRandK(r5, all_keys, 5));
            string l3 = r4;
            string r3 = XORKeyWithE(l4, FunRandK(r4, all_keys, 4));
            string l2 = r3;
            string r2 = XORKeyWithE(l3, FunRandK(r3, all_keys, 3));
            string l1 = r2;
            string r1 = XORKeyWithE(l2, FunRandK(r2, all_keys, 2));
            string l0 = r1;
            string r0 = XORKeyWithE(l1, FunRandK(r1, all_keys, 1));
            string randl = r0 + "" + l0;

            string res = ResAfterIPInverse(randl);
            string res_hexa = FromBinToHex(res);
            return res_hexa;
        }

        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string[] all_keys = KeyExpansion(key);
            string bin_plain_txt = FromHexToBin(plainText);
            string plain_ip = PlainTxtAfterIP(bin_plain_txt);
            string[] splitted_plain = SplitKey(plain_ip);
            string l0 = splitted_plain[0];
            string r0 = splitted_plain[1];
            string l1 = r0;
            string r1 = XORKeyWithE(l0, FunRandK(r0, all_keys, 1));
            string l2 = r1;
            string r2 = XORKeyWithE(l1, FunRandK(r1, all_keys, 2));
            string l3 = r2;
            string r3 = XORKeyWithE(l2, FunRandK(r2, all_keys, 3));
            string l4 = r3;
            string r4 = XORKeyWithE(l3, FunRandK(r3, all_keys, 4));
            string l5 = r4;
            string r5 = XORKeyWithE(l4, FunRandK(r4, all_keys, 5));
            string l6 = r5;
            string r6 = XORKeyWithE(l5, FunRandK(r5, all_keys, 6));
            string l7 = r6;
            string r7 = XORKeyWithE(l6, FunRandK(r6, all_keys, 7));
            string l8 = r7;
            string r8 = XORKeyWithE(l7, FunRandK(r7, all_keys, 8));
            string l9 = r8;
            string r9 = XORKeyWithE(l8, FunRandK(r8, all_keys, 9));
            string l10 = r9;
            string r10 = XORKeyWithE(l9, FunRandK(r9, all_keys, 10));
            string l11 = r10;
            string r11 = XORKeyWithE(l10, FunRandK(r10, all_keys, 11));
            string l12 = r11;
            string r12 = XORKeyWithE(l11, FunRandK(r11, all_keys, 12));
            string l13 = r12;
            string r13 = XORKeyWithE(l12, FunRandK(r12, all_keys, 13));
            string l14 = r13;
            string r14 = XORKeyWithE(l13, FunRandK(r13, all_keys, 14));
            string l15 = r14;
            string r15 = XORKeyWithE(l14, FunRandK(r14, all_keys, 15));
            string l16 = r15;
            string r16 = XORKeyWithE(l15, FunRandK(r15, all_keys, 16));
            string randl = r16 + "" + l16;
            
            string res = ResAfterIPInverse(randl);
            string res_hexa = FromBinToHex(res);
            return res_hexa;
            
        }
        public string FromHexToBin(string hexa)
        {
            string binary = "";
            Dictionary<char, string> hexTobin = new Dictionary<char, string>()
            {
                {'a', "1010"},
                {'b', "1011"},
                {'c', "1100"},
                {'d', "1101"},
                {'e', "1110"},
                {'f', "1111"},
                {'A', "1010"},
                {'B', "1011"},
                {'C', "1100"},
                {'D', "1101"},
                {'E', "1110"},
                {'F', "1111"},
                {'0', "0000"},
                {'1', "0001"},
                {'2', "0010"},
                {'3', "0011"},
                {'4', "0100"},
                {'5', "0101"},
                {'6', "0110"},
                {'7', "0111"},
                {'8', "1000"},
                {'9', "1001"}
            };
            for (int i = 2; i < hexa.Length; i++)
            {
                binary += hexTobin[hexa[i]];
            }

            return binary;
        }
        public string Key_PC1(string prev_key)
        {
            string res = "";
            Dictionary<int, int> from_64_to_56 = new Dictionary<int, int>()
            {
                {57, 0},
                {49, 1},
                {41, 2},
                {33, 3},
                {25, 4},
                {17, 5},
                {9, 6},
                {1, 7},
                {58, 8},
                {50, 9},
                {42, 10},
                {34, 11},
                {26, 12},
                {18, 13},
                {10, 14},
                {2, 15},
                {59, 16},
                {51, 17},
                {43, 18},
                {35, 19},
                {27, 20},
                {19, 21},
                {11, 22},
                {3, 23},
                {60, 24},
                {52, 25},
                {44, 26},
                {36, 27},
                {63, 28},
                {55, 29},
                {47, 30},
                {39, 31},
                {31, 32},
                {23, 33},
                {15, 34},
                {7, 35},
                {62, 36},
                {56, 37},
                {46, 38},
                {38, 39},
                {30, 40},
                {22, 41},
                {14, 42},
                {6, 43},
                {61, 44},
                {53, 45},
                {45, 46},
                {37, 47},
                {29, 48},
                {21, 49},
                {13, 50},
                {5, 51},
                {28, 52},
                {20, 53},
                {12, 54},
                {4, 55},
            };
            foreach (KeyValuePair<int, int> pairs in from_64_to_56)
            {
                char index = prev_key[pairs.Key - 1];
                res += index;
            }
            return res;
        }
        public string[] SplitKey(string key)
        {
            int len = key.Length;
            string c0 = "";
            string d0 = "";
            string[] arr = new string[2];
            for (int i = 0; i < len / 2; i++)
            {
                c0 += key[i];
            }
            for (int i = len / 2; i < len; i++)
            {
                d0 += key[i];
            }
            arr[0] = c0;
            arr[1] = d0;
            return arr;
        }
        public string ShiftKey(string hexa_bin, int round)
        {
            string result = "";
            if (round == 1 || round == 2 || round == 9 || round == 16)
            {
                for (int j = 1; j < hexa_bin.Length; j++)
                {
                    result += hexa_bin[j];
                }
                result += hexa_bin[0];
            }
            else
            {
                for (int j = 2; j < hexa_bin.Length; j++)
                {
                    result += hexa_bin[j];
                }
                result += hexa_bin[0] + "" + hexa_bin[1];
            }
            return result;
        }
        public string bin_plain_txt_48(string c, string d)
        {
            string key = c + "" + d;
            string res = "";
            int[] pc_2 = { 14, 17, 11, 24, 1 ,5, 3, 28, 15, 6, 21, 10,23,19,
                12,4,26,8,16,7,27,20,13,2,41,52,31,37,
                47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
            foreach (int i in pc_2)
            {
                char character = key[i - 1];
                res += character;
            }
            return res;
        }
        public string[] KeyExpansion(string hexa_key)
        {
            string bin_key = FromHexToBin(hexa_key);
            string bin_key_56 = Key_PC1(bin_key);
            string[] splitted_key = SplitKey(bin_key_56);
            string c0 = splitted_key[0];
            string d0 = splitted_key[1];
            string c1 = ShiftKey(c0, 1);
            string d1 = ShiftKey(d0, 1);
            string k1 = bin_plain_txt_48(c1, d1);
            
            string c2 = ShiftKey(c1, 2);
            string d2 = ShiftKey(d1, 2);
            string k2 = bin_plain_txt_48(c2, d2);
            
            string c3 = ShiftKey(c2, 3);
            string d3 = ShiftKey(d2, 3);
            string k3 = bin_plain_txt_48(c3, d3);
            
            string c4 = ShiftKey(c3, 4);
            string d4 = ShiftKey(d3, 4);
            string k4 = bin_plain_txt_48(c4, d4);
            
            string c5 = ShiftKey(c4, 5);
            string d5 = ShiftKey(d4, 5);
            string k5 = bin_plain_txt_48(c5, d5);
           
            string c6 = ShiftKey(c5, 6);
            string d6 = ShiftKey(d5, 6);
            string k6 = bin_plain_txt_48(c6, d6);
            
            string c7 = ShiftKey(c6, 7);
            string d7 = ShiftKey(d6, 7);
            string k7 = bin_plain_txt_48(c7, d7);
            
            string c8 = ShiftKey(c7, 8);
            string d8 = ShiftKey(d7, 8);
            string k8 = bin_plain_txt_48(c8, d8);
           
            string c9 = ShiftKey(c8, 9);
            string d9 = ShiftKey(d8, 9);
            string k9 = bin_plain_txt_48(c9, d9);
            
            string c10 = ShiftKey(c9, 10);
            string d10 = ShiftKey(d9, 10);
            string k10 = bin_plain_txt_48(c10, d10);
           
            string c11 = ShiftKey(c10, 11);
            string d11 = ShiftKey(d10, 11);
            string k11 = bin_plain_txt_48(c11, d11);
           
            string c12 = ShiftKey(c11, 12);
            string d12 = ShiftKey(d11, 12);
            string k12 = bin_plain_txt_48(c12, d12);
            
            string c13 = ShiftKey(c12, 13);
            string d13 = ShiftKey(d12, 13);
            string k13 = bin_plain_txt_48(c13, d13);
            
            string c14 = ShiftKey(c13, 14);
            string d14 = ShiftKey(d13, 14);
            string k14 = bin_plain_txt_48(c14, d14);
            
            string c15 = ShiftKey(c14, 15);
            string d15 = ShiftKey(d14, 15);
            string k15 = bin_plain_txt_48(c15, d15);
            
            string c16 = ShiftKey(c15, 16);
            string d16 = ShiftKey(d15, 16);
            string k16 = bin_plain_txt_48(c16, d16);
           
            string[] keys_arr = { k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15, k16 };
            return keys_arr;
        }
        public string PlainTxtAfterIP(string plain_txt)
        {
            string res = "";
            int[] ip = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,
                54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,
                49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,
                53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
            foreach (int i in ip)
            {
                char character = plain_txt[i - 1];
                res += character;
            }
            return res;
        }

        public string CipherTxtAfterIP(string cipher_txt)
        {
            string res = "";
            int[] ip = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,
                54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,
                49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,
                53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
            foreach (int i in ip)
            {
                char character = cipher_txt[i - 1];
                res += character;
            }
            return res;
        }

        public string RAfterEBit(string r)
        {
            string res = "";
            int[] e_bit_selection = {32,1,2,3,4,5,
                4,5,6,7,8,9,8,9,10,11,12,13,12,13,
                14,15,16,17,16,17,18,19,20,21,20,21
                ,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
            foreach (int i in e_bit_selection)
            {
                char character = r[i - 1];
                res += character;
            }
            return res;
        }
        public string XORKeyWithE(string cell1, string cell2)
        {
            string xor_result = "";

            for (int j = 0; j < cell1.Length; j++)
            {
                if (cell1[j] == cell2[j])
                {
                    xor_result += '0';
                }
                else
                {
                    xor_result += '1';
                }
            }
            return xor_result;
        }

        public int FromBinToDec(string binary)
        {
            Dictionary<string, int> binToDec = new Dictionary<string, int>()
            {
                {"1010", 10},
                {"1011", 11},
                {"1100", 12},
                {"1101", 13},
                {"1110", 14},
                {"1111", 15},
                {"0000", 0},
                {"0001", 1},
                {"0010", 2},
                {"0011", 3},
                {"0100", 4},
                {"0101", 5},
                {"0110", 6},
                {"0111", 7},
                {"1000", 8},
                {"1001", 9},
                {"00", 0},
                {"01", 1},
                {"10", 2},
                {"11", 3}
            };
            //if (binToDec.ContainsKey(binary))
            //{
            //    return binToDec[binary];
            //}
            return binToDec[binary];
        }
        public string FromDecToBin(int num)
        {
            Dictionary<int, string> decTobin = new Dictionary<int, string>()
            {
                {10, "1010"},
                { 11, "1011"},
                { 12, "1100"},
                { 13, "1101"},
                { 14, "1110"},
                { 15, "1111"},
                { 0, "0000"},
                { 1, "0001"},
                { 2, "0010"},
                { 3, "0011"},
                { 4, "0100"},
                { 5, "0101"},
                { 6, "0110"},
                { 7, "0111"},
                { 8, "1000"},
                { 9, "1001"}
            };
            return decTobin[num];
        }
        public string s_box(string xor_res)
        {
            int[,] s1 = { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                        { 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
                        { 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
                        { 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 } };
            int[,] s2 = { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }
                            ,{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 }
                            ,{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 }
                            ,{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 } };
            int[,] s3 = { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }
                            ,{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 }
                            ,{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 }
                            ,{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 } };
            int[,] s4 = { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }
                            ,{13, 8, 11 ,5,6,15,0,3,4,7,2,12,1,10,14,9 }
                            ,{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 }
                            ,{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 } };
            int[,] s5 = { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }
                            ,{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 }
                            ,{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 }
                            ,{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 } };
            int[,] s6 = { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }
                            ,{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 }
                            ,{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 }
                            ,{ 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13} };
            int[,] s7 = { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }
                            ,{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 }
                            ,{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 }
                            ,{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 } };
            int[,] s8 = { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }
                            ,{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 }
                            ,{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 }
                            ,{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11} };
            int parts = xor_res.Length / 8;
            string res = "";
            string b = "";
            int cnt = 0;
            for (int i = 0; i < xor_res.Length; i++)
            {
                b += xor_res[i];
                if (b.Length % 6 == 0)
                {
                    cnt++;
                    string outer = b[0] + "" + b[5];
                    string inner = b[1] + "" + b[2] + "" + b[3] + "" + b[4];
                    int row = FromBinToDec(outer);
                    int column = FromBinToDec(inner);
                    if (cnt == 1)
                    {
                        int res_of_box = s1[row, column];
                        string hexa_res_of_box = FromDecToBin(res_of_box);
                        res += hexa_res_of_box;
                        b = "";
                    }
                    else if (cnt == 2)
                    {
                        int res_of_box = s2[row, column];
                        string hexa_res_of_box = FromDecToBin(res_of_box);
                        res += hexa_res_of_box;
                        b = "";
                    }
                    else if (cnt == 3)
                    {
                        int res_of_box = s3[row, column];
                        string hexa_res_of_box = FromDecToBin(res_of_box);
                        res += hexa_res_of_box;
                        b = "";
                    }
                    else if (cnt == 4)
                    {
                        int res_of_box = s4[row, column];
                        string hexa_res_of_box = FromDecToBin(res_of_box);
                        res += hexa_res_of_box;
                        b = "";
                    }
                    else if (cnt == 5)
                    {
                        int res_of_box = s5[row, column];
                        string hexa_res_of_box = FromDecToBin(res_of_box);
                        res += hexa_res_of_box;
                        b = "";
                    }
                    else if (cnt == 6)
                    {
                        int res_of_box = s6[row, column];
                        string hexa_res_of_box = FromDecToBin(res_of_box);
                        res += hexa_res_of_box;
                        b = "";
                    }
                    else if (cnt == 7)
                    {
                        int res_of_box = s7[row, column];
                        string hexa_res_of_box = FromDecToBin(res_of_box);
                        res += hexa_res_of_box;
                        b = "";
                    }
                    else if (cnt == 8)
                    {
                        int res_of_box = s8[row, column];
                        string hexa_res_of_box = FromDecToBin(res_of_box);
                        res += hexa_res_of_box;
                        b = "";
                    }
                }
            }
            return res;
        }
        public string func_after_p(string plain_txt)
        {
            string res = "";
            int[] p = {16,7,20,21,29,12,28,17,1,
                15,23,26,5,18,31,10,2,8,24,14,32,27
                ,3,9,19,13,30,6,22,11,4,25};
            foreach (int i in p)
            {
                char character = plain_txt[i - 1];
                res += character;
            }
            return res;
        }
        public string ResAfterIPInverse(string txt)
        {
            string res = "";
            int[] ip_inverse = {40,8,48,16,56,24,64,32,
                39,7,47,15,55,23,63,31,
                38,6,46,14,54,22,62,30,
                37,5,45,13,53,21,61,29,
                36,4,44,12,52,20,60,28,
                35,3,43,11,51,19,59,27,
                34,2,42,10,50,18,58,26,
                33,1,41,9,49,17,57,25};
            foreach (int i in ip_inverse)
            {
                char character = txt[i - 1];
                res += character;
            }
            return res;
        }
        public string FunRandK(string R, string[] all_keys, int round)
        {
            string e_R = RAfterEBit(R);
            string xor = XORKeyWithE(e_R, all_keys[round - 1]);
            string after_s_box = s_box(xor);
            string F = func_after_p(after_s_box);
            return F;
        }
        public string FromBinToHex(string binary)
        {
            string hexa = "0x";
            string bin_parts = "";
            Dictionary<char, string> hexTobin = new Dictionary<char, string>()
            {
                {'a', "1010"},
                {'b', "1011"},
                {'c', "1100"},
                {'d', "1101"},
                {'e', "1110"},
                {'f', "1111"},
                {'A', "1010"},
                {'B', "1011"},
                {'C', "1100"},
                {'D', "1101"},
                {'E', "1110"},
                {'F', "1111"},
                {'0', "0000"},
                {'1', "0001"},
                {'2', "0010"},
                {'3', "0011"},
                {'4', "0100"},
                {'5', "0101"},
                {'6', "0110"},
                {'7', "0111"},
                {'8', "1000"},
                {'9', "1001"}
            };
            for (int i = 0; i < binary.Length; i += 4)
            {
                bin_parts += binary[i] + "" + binary[i + 1] + "" + binary[i + 2] + "" + binary[i + 3];
                
                hexa += hexTobin.FirstOrDefault(x => x.Value == bin_parts).Key;
                bin_parts = "";
            }
            
            return hexa;
        }

    }
}
