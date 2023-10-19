#include <cassert>
#include <iomanip>
#include <string>

#include "GOST_28147_89.h"

std::ostream& operator<<(std::ostream& os, const GOST_28147_89::block_t& block)
{
    for (const auto& byte : block)
        os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte)
           << ' ';
    return os;
}

// 1. �������� ���� �� 8 ������ �� 4 �������
//     A B C D | E F G H | I J K L | M N O P | Q R S T | U V W X | A B C D | E F G H
// 2. ������������ ������ ���� (A B C D) � 32 ������ �����.
// 3. ��������� ����������� ������ �����
//     A -> 0x41 (����������� � 16�� �������) -> 0x41000000 (�������� �� 24 ���� �����)
// 4. ��������� ��� ����� ��� ������ ���������� ���
//     0x41000000 | 0x00420000 | 0x00004300 | 0x00000044 = 0x41424344
// 5. ������� �������� ���������
//     0x41424344 0x45464748 0x494A4B4C 0x4D4E4F50 0x51525354 0x55565758 0x41424344
//     0x45464748
GOST_28147_89::GOST_28147_89(const char* key)
{
    // ����������� ���������� ���� ����� ����� �� ������������ 32 ������.
    assert(strlen(key) == 32 && "Key must be 32 bytes long.");

#ifdef PR_DEBUG
    std::cout << "[ Cipher key ]: ";
#endif // DEBUG
    for (size_t i = 0; i < 8; ++i) {
        m_key[i] =
            static_cast<uint32_t>(static_cast<unsigned char>(key[4 * i]) << 24)
            | static_cast<uint32_t>(static_cast<unsigned char>(key[4 * i + 1]) << 16)
            | static_cast<uint32_t>(static_cast<unsigned char>(key[4 * i + 2]) << 8)
            | static_cast<uint32_t>(static_cast<unsigned char>(key[4 * i + 3]));

#ifdef PR_DEBUG
        std::cout << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << m_key[i] << " ";
#endif // DEBUG
    }

#ifdef PR_DEBUG
    std::cout << std::endl << std::endl;
#endif // DEBUG
}

void GOST_28147_89::setInitializationVector(const char* iv)
{
    assert(strlen(iv) == 8 && "Initialization vector must be exactly 8 bytes long.");

    for (size_t i = 0; i < 8; ++i)
        m_initialization_vector[i] = static_cast<byte_t>(iv[i]);
}

uint32_t GOST_28147_89::f(const std::array<byte_t, 4>& A, const uint32_t& key)
{
    // ��������� (2^32). C �� ������� ����� ���������� � 32-�����.
    static const uint64_t MODULO = 1ull << 32;
    uint64_t A_bits              = (blockToBits<uint32_t>(A) + key) % MODULO;

    /**
     * ���� ��������� �������� ����������� (������) �� 4-������ ������ ����� A_bits,
     * ��������� ������� ����� m_s_blocks.
     *
     * ��������, ���� A_bits = 0xB0EE439B, �� i = 0:
     * - ��������� 4 ���� �� A_bits �� ������� 0 (����� ������ 4 ����). �������� 0xB.
     * - ���������� ��� �������� ��� ������ � ������ ������� �����. ��������
     * m_s_blocks[0][0xB] = 0xC.
     * - ����������� �������� four_bit_blocks[7] (�.�. ������� � ����� ��������) ��������
     * 0xC.
     *
     * ��������� ��� �������� ��� ������� 4-������� ����� A_bits.
     */
    block_t four_bit_blocks = { 0, 0, 0, 0, 0, 0, 0, 0 };
    for (size_t i = 0; i < 8; ++i)
        four_bit_blocks[7 - i] = m_s_blocks.at(i).at(extract4Bits(A_bits, i));

    // �������������� ����� ������� � 32�� �����.
    uint32_t res = blockToBits<uint32_t>(four_bit_blocks);
    // ���������� ������������ ������ �� 11 ������� �����.
    return ((res << 11) | (res >> 21));
}

GOST_28147_89::block_t GOST_28147_89::block_cipher(const std::array<uint32_t, 8>& __key,
                                                   const block_t& text_block)
{
    // [ INPUT BLOCK ]: 48 65 6C 6C 6F 2C 20 57
#ifdef PR_DEBUG
    std::cout << std::setfill('-') << std::setw(50) << "\n";
    std::cout << "[ KEY ]\t\t: ";
    for (const auto& b : __key)
        std::cout << b << " ";
    std::cout << std::endl;
    std::cout << "[ INPUT BLOCK ]\t: " << text_block << std::endl;
#endif

    // ��������� ���������� 8-�������� ����� �� ��� 4-������� �����.
    // B: 0x48656C6C (ASCII ������������� "Hell")
    // A: 0x6F2C2057 (ASCII ������������� "o, W")
    std::array<byte_t, 4> B = {
        text_block[0],
        text_block[1],
        text_block[2],
        text_block[3],
    };
    std::array<byte_t, 4> A = {
        text_block[4],
        text_block[5],
        text_block[6],
        text_block[7],
    };

    // 32 ������ ����������, ���������� �� ���� ��������
    for (size_t key, i = 0; i < 32; ++i) {
        // ���������� ������� ���� ��� ������
        // ������ 1 - 8 : key[0]->key[7]
        // ������ 9 - 16 : key[0]->key[7]
        // ������ 17 - 24 : key[0]->key[7]
        // ������ 25 - 32 : key[7]->key[0]
        // ��� �������� ����� (��� CBC) ������ ��� ��������
        key = (m_key == __key) ? __key.at(i < 24 ? i % 8 : 31 - i)
                               : __key.at(i < 8 ? 7 - i : i % 8);

        // ���������� �������� XOR � ����� B � ���������� ������� f, ����������� � ����� A
        // � �������� �����
        uint32_t B_bits = blockToBits<uint32_t>(B) ^ f(A, key);

        /// ���������� �������� �� A � B � �� B_bits � A ��� ���������� ������.
        B = A;
        A = bitsToBlock<uint32_t, A.size()>(B_bits);
    }

    block_t output = {
        A[0], A[1], A[2], A[3], B[0], B[1], B[2], B[3],
    };
#ifdef PR_DEBUG
    std::cout << "[ OUT BLOCK ]\t: " << output << std::endl;
    std::cout << std::setfill('-') << std::setw(50) << "\n";
#endif
    return output;
};

std::string GOST_28147_89::processStream(Method method,
                                         const std::array<uint32_t, 8>& key,
                                         bool isEncrypt)
{
    std::string result;
    block_t block, prev, xored, temp;

    prev = m_initialization_vector;

    std::array<uint32_t, 8> usedKey =
        isEncrypt ? key : std::array<uint32_t, 8> { key[7], key[6], key[5], key[4],
                                                    key[3], key[2], key[1], key[0] };
    // ECB (Electronic Codebook) Mode:
    // ������ ������� ��� ��������� ������ ���� ������ ����������.
    auto handleECB = [&]() { return block_cipher(usedKey, block); };

    // CBC (Cipher Block Chaining) Mode:
    // ������ ���� ������ ����� ����������� XOR-���� � ���������� ������ �������������
    // ������. ��� ������ ������ ���� ��������� �� ���� ���������� ������.
    auto handleCBC = [&]()
    {
        if (isEncrypt) {
            xored = block ^ prev;
            prev  = block_cipher(usedKey, xored);
            return prev;
        } else {
            temp  = block;
            xored = block_cipher(usedKey, block) ^ prev;
            prev  = temp;
            return xored;
        }
    };

    // CFB (Cipher Feedback) Mode:
    // ����� �� ����� CBC, �� ������ ���� ����� XOR-��� ���� ������ � ����������
    // ������ ������������� ������, �� XOR-���� � ���������� ������ ��������������
    // ��������� ������.
    auto handleCFB = [&]()
    {
        xored = block ^ block_cipher(m_key, prev);
        prev  = isEncrypt ? xored : block;
        return xored;
    };

    // OFB (Output Feedback) Mode:
    // ���� ������ XOR-���� � ������������� ��������� ����������� �����.
    auto handleOFB = [&]()
    {
        prev = block_cipher(m_key, prev);
        return block ^ prev;
    };

#ifdef PR_DEBUG
    (isEncrypt) ? std::cout << "\n\t\t[ ENCRYPTED ]\n"
                            << std::endl
                : std::cout << "\n\t\t[ DECRYPTED ]\n"
                            << std::endl;
    std::cout << std::setfill('=') << std::setw(50) << "\n";
#endif
    // ��������������� ��������� ������� ����� �� ����� ������ �� 8 ���� � ������������
    // ��, ���� �� �� ����������.
    while (!m_stream->eof()) {
        block = read_block();
        switch (method) {
            case Method::ECB: block = handleECB(); break;
            case Method::CBC: block = handleCBC(); break;
            case Method::CFB: block = handleCFB(); break;
            case Method::OFB: block = handleOFB(); break;
            default: break;
        }
        result += blockToString(block);
    }
#ifdef PR_DEBUG
    std::cout << std::setfill('=') << std::setw(50) << "\n";
#endif
    return result;
}

void GOST_28147_89::encrypt(Method method, std::istream& is, std::ostream& os)
{
    m_stream = &is;
    os << processStream(method, m_key, true);
}

void GOST_28147_89::decrypt(Method method, std::istream& is, std::ostream& os)
{
    m_stream = &is;
    os << processStream(method, m_key, false);
}

GOST_28147_89::block_t GOST_28147_89::read_block()
{
    block_t block = { 0, 0, 0, 0, 0, 0, 0, 0 }; // �������������� ���� ������

    m_stream->read(reinterpret_cast<char*>(block.data()),
                   8); // ������ �� 8 ������ �������� � ����
    m_stream->peek();  // ���������� �������� EOF (EndOfFile)

#ifdef PR_DEBUG
    std::cout << "[ READ ]\t: ";
    for (const auto& b : block)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b)
                  << " ";
    std::cout << std::endl;
#endif

    return block;
}

//
// Utilities
//

template <size_t S>
std::string GOST_28147_89::blockToString(const std::array<byte_t, S>& text_block)
{
    return std::string(text_block.begin(), text_block.end());
}

template <typename T, size_t S>
T GOST_28147_89::blockToBits(const std::array<byte_t, S>& block)
{
    T bits = 0;
    for (size_t i = 0; i < block.size(); ++i)
        bits |= static_cast<T>(block[i]) << (S - i - 1) * (sizeof(T) + S % 8);
    return bits;
}

template <typename T, size_t S>
std::array<GOST_28147_89::byte_t, S> GOST_28147_89::bitsToBlock(const T& bits)
{
    std::array<byte_t, S> result;
    for (size_t i = 0; i < S; ++i)
        result[i] = (bits >> 8 * (S - i - 1)) & 0xFF;
    return result;
};

/**
 * ������:
 * ���� num = 0xA23FB45CDE678910 � position = 3:
 * 1. ��������� ����� ��� �����: (0xFull << (position * 4))
 *    0xFull = 1111 (� �������� ����)
 *    position * 4 = 12 (�������� �� 12 ����� �����)
 *    ����� ����������: 0xF000
 * 2. ��������� �������� � (bitwise AND) ����� num � ������. ��� �������� ��� ���� � num,
 * ����� ������������� ��� 4-������� �����.
 *    num & 0xF000 = 0xB0000
 * 3. �������� ��������� �� (position * 4) ������� ������, ����� �������� ��������
 * 4-������ ��������. 0xB0000 >> 12 = 0xB ������� ����� �������� 0xB ��� ����������
 * �������.
 */
inline uint32_t GOST_28147_89::extract4Bits(const uint64_t num, const size_t position)
{
    return (num & (0xFull << (position * 4))) >> (position * 4);
}