using static System.Console;
using System.Text;

namespace Magma
{
    public class MagmaEncrypt
    {
        byte[,] keys;
        int[,] Pi = new int[,]
                {
                  {1,7,14,13,0,5,8,3,4,15,10,6,9,12,11,2},
                  {8,14,2,5,6,9,1,12,15,4,11,0,13,10,3,7},
                  {5,13,15,6,9,2,12,10,11,7,8,1,4,3,14,0},
                  {7,15,5,10,8,1,6,13,0,9,3,14,11,4,2,12},
                  {12,8,2,1,13,4,15,6,7,0,10,5,3,14,9,11},
                  {11,3,5,8,2,15,10,13,14,1,7,4,12,9,6,0},
                  {6,8,2,3,9,10,5,12,1,14,4,7,11,13,0,15},
                  {12,4,6,2,10,5,11,9,14,8,13,7,0,3,15,1}
                };

        public MagmaEncrypt(string key)
        {
            byte[] asciiKey = Encoding.GetEncoding(1251).GetBytes(key);
            keys = new byte[8, 4];
            for (int i = 0; i < 8; i++)
                for (int j = 0; j < 4; j++)
                    keys[i, j] = asciiKey[i * 4 + j];
        }

        public void KeySum(byte[] second_part, byte[,] keys, int round)
        {
            uint _byte = 0;
            uint[] _key = new uint[8];
            for (int i = 0; i < 4; i++)
            {
                _byte = _byte << 8;
                _byte += second_part[i];
            }
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    _key[i] = _key[i] << 8;
                    _key[i] += keys[i, j];
                }
            }
            _byte += _key[round < 24 ? round % 8 : (7 - round % 8)];

            for (int i = 0; i < 4; i++)
            {
                second_part[i] = (byte)(_byte >> 24);
                _byte = _byte << 8 | _byte >> 24;
            }
        }

        public void T(byte[] second_part)
        {
            for (int i = 0; i < 4; i++)
            {
                byte first_part_byte = (byte)((second_part[i] & 0xf0) >> 4);
                byte sec_part_byte = (byte)((second_part[i] & 0x0f));
                first_part_byte = (byte)Pi[i * 2, first_part_byte];
                sec_part_byte = (byte)Pi[i * 2 + 1, sec_part_byte];
                second_part[i] = (byte)((first_part_byte << 4) | sec_part_byte);
            }
        }

        public void Offset(byte[] second_part)
        {
            uint _byte = 0;
            for (int i = 0; i < 4; i++)
            {
                _byte = _byte << 8;
                _byte += second_part[i];
            }
            _byte = _byte << 11 | _byte >> 21;
            for (int i = 0; i < 4; i++)
            {
                second_part[i] = (byte)(_byte >> 24);
                _byte = _byte << 8 | _byte >> 24;
            }
        }

        public void Xor(byte[] first_part, byte[] second_part)
        {
            for (int i = 0; i < 4; i++)          
                second_part[i] = (byte)(second_part[i] ^ first_part[i]);          
        }

        public string Crypt(byte[] asciiBytes)
        {
            string encrypt_str = "";
            byte[] first_part = new byte[4];
            byte[] second_part = new byte[4];
            byte[] temp = new byte[4];
            for (int j = 0; j < 4; j++)
            {
                first_part[j] = asciiBytes[j];
                second_part[j] = asciiBytes[j + 4];
            }
            second_part.CopyTo(temp, 0);
            for (int round = 0; round < 32; round++)
            {
                KeySum(second_part, keys, round);
                T(second_part);
                Offset(second_part);
                Xor(first_part, second_part);
                temp.CopyTo(first_part, 0);
                second_part.CopyTo(temp, 0);
                if (round == 31)
                {
                    byte b;
                    for (int j = 0; j < 4; j++)
                    {
                        b = first_part[j];
                        first_part[j] = second_part[j];
                        second_part[j] = b;
                    }
                    encrypt_str += Encoding.GetEncoding(1251).GetString(first_part);
                    encrypt_str += Encoding.GetEncoding(1251).GetString(second_part);
                }
            }
            return encrypt_str;
        }      
    }

    public class Program
    {
        static void Xor(byte[] asciiBytes, byte[] asciiVector)
        {
            for (int i = 0; i < 8; i++)           
                asciiVector[i] = (byte)(asciiVector[i] ^ asciiBytes[i]);           
        }

        static string Crypt(string str, string key, string vector, char mode) //Режим гаммирования с обратной связью
        {
            str = str.Length % 8 == 0 ? str : str.PadRight(str.Length + (8 - str.Length % 8), '\0');
            MagmaEncrypt magma = new MagmaEncrypt(key);
            string encrypt_str = "";
            byte[] asciiVector = Encoding.GetEncoding(1251).GetBytes(vector);
            for (int i = 0; i < str.Length; i += 8)
            {
                byte[] asciiBytes = Encoding.GetEncoding(1251).GetBytes(str.Substring(i, 8));
                asciiVector = Encoding.GetEncoding(1251).GetBytes(magma.Crypt(asciiVector));
                Xor(asciiBytes, asciiVector);
                encrypt_str += Encoding.GetEncoding(1251).GetString(asciiVector);
                if (mode=='D')
                    asciiVector = asciiBytes;

            }
            return encrypt_str;
        }

        static void Main(string[] args)
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            Write("введите текст шифрования: ");
            string str = "hello world! world hello! hello hello!";
            //Write("Введите текст для шифрования: ");
            //string str = ReadLine();
            string key = "12345678901234567890123456789012";
            //Write("Введите ключ шифрования: ");
            //string key = ReadLine();
            string vector = "abcdefgh";
            //Write("Введите вектор инициализации: ");
            //string vector = ReadLine();
            WriteLine($"Исходная строка: {str}");
            WriteLine($"Ключ шифрования: {key}");
            WriteLine($"Вектор инициализации: {vector}\n");
            string encrypt_str = Crypt(str, key, vector, 'E');
            WriteLine($"Зашифрованная строка: {encrypt_str}");
            string decrypt_str = Crypt(encrypt_str, key, vector, 'D');
            WriteLine($"Расшифрованная строка: {decrypt_str}");
        }
    }
}