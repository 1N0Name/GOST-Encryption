#ifndef GOST_28147_89_H
#define GOST_28147_89_H

#include <array>
#include <fstream>
#include <iostream>
#include <vector>

class GOST_28147_89
{
public:
    enum class Method
    {
        ECB, // Electronic Codebook
        CBC, // Cipher Block Chaining
        CFB, // Cipher Feedback
        OFB, // Output Feedback
    };

    using byte_t  = unsigned char;
    using block_t = std::array<byte_t, 8>;

    /**
     * ����������� ������ ��� ���������� ���� 28147-89.
     * �������������� ������ � �������� ������.
     * ���� ������ ����� ������ 32 �����.
     * @param key ��������� �� ���������� ������������� �����.
     */
    GOST_28147_89(const char* key);

    /**
     * ������ ������ �������������.
     * ������ ������������� - ��������� ����� ������, ������� ����������� � ���������
     * ������ ����� �����������. �� �����������, ��� ���� ���������� ����� ���������
     * ������ ����� ����������������� � ������ ����� �����������.
     *
     * @param iv - ������ ������������� (8 ��������).
     */
    void setInitializationVector(const char* iv);
    void encrypt(Method method, std::istream& is, std::ostream& os);
    void decrypt(Method method, std::istream& is, std::ostream& os);

private:
    /**
     * id-Gost28147-89-CryptoPro-A-ParamSet
     * https://ru.wikipedia.org/wiki/%D0%93%D0%9E%D0%A1%D0%A2_28147-89#%D0%98%D0%B4%D0%B5%D0%BD%D1%82%D0%B8%D1%84%D0%B8%D0%BA%D0%B0%D1%82%D0%BE%D1%80:_id-Gost28147-89-CryptoPro-A-ParamSet
     * ������� ����������� (S-�����) ��� GOST 28147-89.
     */
    // clang-format off
    static constexpr std::array<std::array<GOST_28147_89::byte_t, 16>, 8> m_s_blocks = {
        0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5,
        0x3, 0x7, 0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1,
        0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7, 0x1, 0x9,
        0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6,
        0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6,
        0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5, 0x9, 0x4, 0x8, 0xF, 0xE, 0x6,
        0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3, 0xB, 0xE,
        0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7, 0xD, 0x4,
    };
    // clang-format on

    std::string processStream(Method method, const std::array<uint32_t, 8>& key,
                              bool isEncrypting);

    /**
     * ������ ���� �� �������� ������ (8 ����).
     * @return ���� ������.
     */
    block_t read_block();

    /**
     * ����������� ���� ������ � �����.
     * @param block - ���� ������.
     * @return �����, �������������� ���� ������.
     */
    template <typename T, size_t S>
    T blockToBits(const std::array<byte_t, S>& block);

    /**
     * ����������� ���� ������ � ������.
     * @param text_block - ���� ������.
     * @return ������, �������������� ���� ������.
     */
    template <size_t S>
    std::string blockToString(const std::array<byte_t, S>& text_block);

    /**
     * ����������� ����� � ���� ������.
     * @param bits - �����.
     * @return ���� ������, �������������� �����.
     */
    template <typename T, size_t S>
    std::array<byte_t, S> bitsToBlock(const T& bits);

    /**
     * ��������� 4-������ ���� �� 64-������� ����� �� �������� �������.
     * @param num 64-������ �����, �� �������� ����� ��������� ����.
     * @param position �������, � ������� ���������� 4-������ ����. ������� 0
     * ������������� ������� (����� ������) 4-� �����.
     * @return ����������� 4-������ ��������.
     */
    inline uint32_t extract4Bits(const uint64_t num, const size_t position);

    /**
     * ��������� S-����� � 32-������� ����� � �����.
     * @param A - 32-������ ����� � ���� ������� �� 4 ����.
     * @param key - ����� �����.
     * @return ��������� ���������� S-������.
     */
    uint32_t f(const std::array<byte_t, 4>& A, const uint32_t& key);

    /**
     * ��������� ������� ���������� (�������� �� ���� ��������) � ����� ������.
     * @param __key - ���� ����������.
     * @param text_block - ���� ������.
     * @return ������������� ����.
     */
    block_t block_cipher(const std::array<uint32_t, 8>& __key, const block_t& text_block);

    // Private Fields
    std::istream* m_stream;
    std::array<uint32_t, 8> m_key;
    block_t m_initialization_vector;
};

#endif // !GOST_28147_89_H

template <size_t S>
inline std::array<GOST_28147_89::byte_t, S>
operator^(const std::array<GOST_28147_89::byte_t, S>& left,
          const std::array<GOST_28147_89::byte_t, S>& right)
{
    std::array<GOST_28147_89::byte_t, S> result;
    for (size_t i = 0; i < S; ++i)
        result[i] = left[i] ^ right[i];
    return result;
}