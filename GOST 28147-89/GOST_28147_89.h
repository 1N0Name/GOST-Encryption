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
     * Конструктор класса для шифрования ГОСТ 28147-89.
     * Инициализирует объект с заданным ключом.
     * Ключ должен иметь размер 32 байта.
     * @param key Указатель на символьное представление ключа.
     */
    GOST_28147_89(const char* key);

    /**
     * Задает вектор инициализации.
     * Вектор инициализации - небольшой кусок данных, который добавляется к открытому
     * тексту перед шифрованием. Он гарантирует, что даже одинаковые блоки открытого
     * текста будут преобразовываться в разные блоки шифротекста.
     *
     * @param iv - вектор инициализации (8 символов).
     */
    void setInitializationVector(const char* iv);
    void encrypt(Method method, std::istream& is, std::ostream& os);
    void decrypt(Method method, std::istream& is, std::ostream& os);

private:
    /**
     * id-Gost28147-89-CryptoPro-A-ParamSet
     * https://ru.wikipedia.org/wiki/%D0%93%D0%9E%D0%A1%D0%A2_28147-89#%D0%98%D0%B4%D0%B5%D0%BD%D1%82%D0%B8%D1%84%D0%B8%D0%BA%D0%B0%D1%82%D0%BE%D1%80:_id-Gost28147-89-CryptoPro-A-ParamSet
     * Матрица подстановок (S-блоки) для GOST 28147-89.
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
     * Читает блок из входного потока (8 байт).
     * @return Блок данных.
     */
    block_t read_block();

    /**
     * Преобразует блок данных в число.
     * @param block - блок данных.
     * @return Число, представляющее блок данных.
     */
    template <typename T, size_t S>
    T blockToBits(const std::array<byte_t, S>& block);

    /**
     * Преобразует блок данных в строку.
     * @param text_block - блок данных.
     * @return Строка, представляющая блок данных.
     */
    template <size_t S>
    std::string blockToString(const std::array<byte_t, S>& text_block);

    /**
     * Преобразует число в блок данных.
     * @param bits - число.
     * @return Блок данных, представляющий число.
     */
    template <typename T, size_t S>
    std::array<byte_t, S> bitsToBlock(const T& bits);

    /**
     * Извлекает 4-битный блок из 64-битного числа на заданной позиции.
     * @param num 64-битное число, из которого будут извлечены биты.
     * @param position Позиция, с которой начинается 4-битный блок. Позиция 0
     * соответствует младшим (самым правым) 4-м битам.
     * @return Извлеченное 4-битное значение.
     */
    inline uint32_t extract4Bits(const uint64_t num, const size_t position);

    /**
     * Применяет S-блоки к 32-битному числу и ключу.
     * @param A - 32-битное число в виде массива из 4 байт.
     * @param key - часть ключа.
     * @return Результат применения S-блоков.
     */
    uint32_t f(const std::array<byte_t, 4>& A, const uint32_t& key);

    /**
     * Применяет функцию шифрования (основную на сети Фейстеля) к блоку текста.
     * @param __key - ключ шифрования.
     * @param text_block - блок текста.
     * @return Зашифрованный блок.
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