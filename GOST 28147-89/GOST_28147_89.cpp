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

// 1. Разобьем ключ на 8 блоков по 4 символа
//     A B C D | E F G H | I J K L | M N O P | Q R S T | U V W X | A B C D | E F G H
// 2. Конвертируем первый блок (A B C D) в 32 битное число.
// 3. Поочереди преобразуем каждую букву
//     A -> 0x41 (преобразуем в 16ую систему) -> 0x41000000 (сдвигаем на 24 бита влево)
// 4. Объединим все буквы при помощи побитового или
//     0x41000000 | 0x00420000 | 0x00004300 | 0x00000044 = 0x41424344
// 5. Получим итоговый результат
//     0x41424344 0x45464748 0x494A4B4C 0x4D4E4F50 0x51525354 0x55565758 0x41424344
//     0x45464748
GOST_28147_89::GOST_28147_89(const char* key)
{
    // Выбрасываем исключение если длина ключа не соответсвует 32 байтам.
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
    // Константа (2^32). C ее помощью числа приводится к 32-битам.
    static const uint64_t MODULO = 1ull << 32;
    uint64_t A_bits              = (blockToBits<uint32_t>(A) + key) % MODULO;

    /**
     * Цикл выполняет операцию подстановки (замены) на 4-битных блоках числа A_bits,
     * используя таблицы замен m_s_blocks.
     *
     * Например, если A_bits = 0xB0EE439B, то i = 0:
     * - Извлекаем 4 бита из A_bits на позиции 0 (самые правые 4 бита). Получаем 0xB.
     * - Используем это значение как индекс в первой таблице замен. Получаем
     * m_s_blocks[0][0xB] = 0xC.
     * - Присваиваем значение four_bit_blocks[7] (т.е. первому с конца элементу) значение
     * 0xC.
     *
     * Повторяем эти действия для каждого 4-битного блока A_bits.
     */
    block_t four_bit_blocks = { 0, 0, 0, 0, 0, 0, 0, 0 };
    for (size_t i = 0; i < 8; ++i)
        four_bit_blocks[7 - i] = m_s_blocks.at(i).at(extract4Bits(A_bits, i));

    // Преобразование блока обратно в 32ое число.
    uint32_t res = blockToBits<uint32_t>(four_bit_blocks);
    // Выполнение циклического сдвига на 11 позиций влево.
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

    // Начальное разделение 8-байтного блока на две 4-байтные части.
    // B: 0x48656C6C (ASCII представление "Hell")
    // A: 0x6F2C2057 (ASCII представление "o, W")
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

    // 32 раунда шифрования, основанные на сети Фейстеля
    for (size_t key, i = 0; i < 32; ++i) {
        // Определяем текущий ключ для раунда
        // Раунды 1 - 8 : key[0]->key[7]
        // Раунды 9 - 16 : key[0]->key[7]
        // Раунды 17 - 24 : key[0]->key[7]
        // Раунды 25 - 32 : key[7]->key[0]
        // При обратном ключе (для CBC) делаем все наоборот
        key = (m_key == __key) ? __key.at(i < 24 ? i % 8 : 31 - i)
                               : __key.at(i < 8 ? 7 - i : i % 8);

        // Применение операции XOR к блоку B и результату функции f, примененной к блоку A
        // и текущему ключу
        uint32_t B_bits = blockToBits<uint32_t>(B) ^ f(A, key);

        /// Перемещаем значение из A в B и из B_bits в A для следующего раунда.
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
    // Просто шифрует или дешифрует каждый блок данных независимо.
    auto handleECB = [&]() { return block_cipher(usedKey, block); };

    // CBC (Cipher Block Chaining) Mode:
    // Каждый блок данных перед шифрованием XOR-ится с предыдущим блоком зашифрованных
    // данных. Это делает каждый блок зависимым от всех предыдущих блоков.
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
    // Похож на режим CBC, но вместо того чтобы XOR-ить блок данных с предыдущим
    // блоком зашифрованных данных, он XOR-ится с предыдущим блоком зашифрованного
    // открытого текста.
    auto handleCFB = [&]()
    {
        xored = block ^ block_cipher(m_key, prev);
        prev  = isEncrypt ? xored : block;
        return xored;
    };

    // OFB (Output Feedback) Mode:
    // Блок данных XOR-ится с зашифрованным значением предыдущего блока.
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
    // Последовательно разбиваем входной поток на блоки данных по 8 байт и обрабатываем
    // их, пока он не закончится.
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
    block_t block = { 0, 0, 0, 0, 0, 0, 0, 0 }; // Инициализируем блок нулями

    m_stream->read(reinterpret_cast<char*>(block.data()),
                   8); // Читаем до 8 байтов напрямую в блок
    m_stream->peek();  // Обновление значения EOF (EndOfFile)

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
 * Пример:
 * Если num = 0xA23FB45CDE678910 и position = 3:
 * 1. Вычисляем маску для битов: (0xFull << (position * 4))
 *    0xFull = 1111 (в двоичном виде)
 *    position * 4 = 12 (сдвигаем на 12 битов влево)
 *    Маска становится: 0xF000
 * 2. Применяем операцию И (bitwise AND) между num и маской. Это обнуляет все биты в num,
 * кроме интересующего нас 4-битного блока.
 *    num & 0xF000 = 0xB0000
 * 3. Сдвигаем результат на (position * 4) позиций вправо, чтобы получить итоговое
 * 4-битное значение. 0xB0000 >> 12 = 0xB Функция вернёт значение 0xB для указанного
 * примера.
 */
inline uint32_t GOST_28147_89::extract4Bits(const uint64_t num, const size_t position)
{
    return (num & (0xFull << (position * 4))) >> (position * 4);
}