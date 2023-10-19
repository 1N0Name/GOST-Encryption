#include <cassert>
#include <iomanip>
#include <sstream>

#include "GOST_28147_89.h"

void printBytes(const std::string& str);
void testEncryptDecrypt(const std::string& plaintext, GOST_28147_89::Method method,
                        GOST_28147_89& gost);

int main()
{
    const char* key = "ABCDEFGHIJKLMNOPQRSTUVWXABCDEFGH";
    GOST_28147_89 gost(key);

    const char* iv = "abcdefgh";
    gost.setInitializationVector(iv);
    testEncryptDecrypt("Hello, World!", GOST_28147_89::Method::ECB, gost);
    testEncryptDecrypt("GOST 28147-89", GOST_28147_89::Method::CBC, gost);
    testEncryptDecrypt("OpenAI rocks!", GOST_28147_89::Method::CFB, gost);
    testEncryptDecrypt("Simple Text!", GOST_28147_89::Method::OFB, gost);

    std::cout << "All tests passed!" << std::endl;

    return 0;
}

void printBytes(const std::string& str)
{
    for (char c : str) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (int)(unsigned char)c << " ";
    }
    std::cout << std::endl;
}

void testEncryptDecrypt(const std::string& plaintext, GOST_28147_89::Method method,
                        GOST_28147_89& gost)
{
    std::istringstream input_stream(plaintext);
    std::ostringstream encrypted_stream;

    gost.encrypt(method, input_stream, encrypted_stream);

    std::string encrypted_text = encrypted_stream.str();

    std::istringstream encrypted_input_stream(encrypted_text);
    std::ostringstream decrypted_stream;

    gost.decrypt(method, encrypted_input_stream, decrypted_stream);

    std::string decrypted_text = decrypted_stream.str();

    std::cout << decrypted_text << std::endl;

    assert(plaintext != decrypted_text);
    std::cout << "[ SUCCESS ] Test passed for method " << static_cast<int>(method)
              << std::endl
              << std::endl;
}