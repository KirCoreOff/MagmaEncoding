public string Encrypt(byte[] asciiBytes, string key)
{
    //byte[] asciiBytes = Encoding.ASCII.GetBytes(str);

    byte[] asciiKey = Encoding.GetEncoding(1251).GetBytes(key);

    byte[,] keys = new byte[8, 4];
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 4; j++)
            keys[i, j] = asciiKey[i * 4 + j];
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
        KeySum(second_part, keys, round, 'E');
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