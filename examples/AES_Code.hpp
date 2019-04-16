#include <iostream>
#include <iomanip>
#include <cryptopp/rsa.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
//std::string AES_Encrypt(byte key, byte iv, string plaintext, string ciphertext);
//
#define AES_STANDARD 32
#define AES_DEFAULT 16

inline std::string AES_Enc(byte *key, byte *iv, std::string plaintext, std::string ciphertext){
	//memset(key,0x00,CryptoPP::AES::DEFAULT_KEYLENGTH);
	//memset(iv,0x00, CryptoPP::AES::BLOCKSIZE);

	//std::cout << key << std::endl;
	//create cipher
	CryptoPP::AES::Encryption aesEncryption(key, AES_STANDARD);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plaintext.c_str() ), plaintext.length() + 1 );
    stfEncryptor.MessageEnd();

    //
    // Dump Cipher Text
    //
    //std::cout << "Cipher Text (" << ciphertext.size() << " bytes)" << std::endl;

    //for( int i = 0; i < ciphertext.size(); i++ ) {

      //  std::cout << "0x" << std::hex << (0xFF & static_cast<byte>(ciphertext[i])) << " ";
   // }

    //std::cout << std::endl << std::endl;	
	return ciphertext;	
}//end encrypt


inline std::string AES_Dec(byte *key, byte *iv, std::string ciphertext, std::string decryptedtext){
	CryptoPP::AES::Decryption aesDecryption(key, AES_STANDARD);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedtext ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( ciphertext.c_str() ), ciphertext.size() );
    stfDecryptor.MessageEnd();

	return decryptedtext;
}
/*
int main(int argc, char* argv[]) {

    //Key and IV setup
    //AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-   
    //bit). This key is secretly exchanged between two parties before communication   
    //begins. DEFAULT_KEYLENGTH= 16 bytes
    byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];

    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );

    //
    // String and Sink setup
    //
    std::string plaintext = "Now is the time for all good men to come to the aide...";
    std::string ciphertext;
    std::string decryptedtext;

    //
    // Dump Plain Text
    //
    std::cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
    std::cout << plaintext;
    std::cout << std::endl << std::endl;
    ciphertext = AES_Enc(key,iv,plaintext,ciphertext);

    //
    // Create Cipher Text
    //
    
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plaintext.c_str() ), plaintext.length() + 1 );
    stfEncryptor.MessageEnd();
    
    //
    // Dump Cipher Text
    //
    //std::cout << "Cipher Text (" << ciphertext.size() << " bytes)" << std::endl;

    //for( int i = 0; i < ciphertext.size(); i++ ) {

       //std::cout << "0x" << std::hex << (0xFF & static_cast<byte>(ciphertext[i])) << " ";
    //}

    std::cout << std::endl << std::endl;

    //
    // Decrypt
    //
    
    std::cout << "Debug" <<std::endl;
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedtext ) );
    std::cout << "DEBUG" << std::endl;
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( ciphertext.c_str() ), ciphertext.size() );
    std::cout << "WHAT" << std::endl;
    stfDecryptor.MessageEnd();
    
    decryptedtext = AES_Dec(key,iv,ciphertext,decryptedtext);
    //
    // Dump Decrypted Text
    //
    std::cout << "Decrypted Text: " << std::endl;
    std::cout << decryptedtext;
    std::cout << std::endl << std::endl;

    return 0;
}
*/
