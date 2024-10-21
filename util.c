#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/**
 * @brief Выводит справку по использованию программы.
 */
void print_usage() {
    printf("Использование: ./gmac_util -f <файл> -p <пароль> [-o <файл для iv и соли>]\n");
}

/**
 * @brief Генерирует случайный вектор и соль.
 * 
 * @param iv Указатель на массив для хранения вектора инициализации.
 * @param salt Указатель на массив для хранения соли.
 * @param iv_len Длина вектора инициализации.
 * @param salt_len Длина соли.
 * @return int Возвращает 0 в случае успеха, иначе -1.
 */
int generate_iv_and_salt(unsigned char *iv, unsigned char *salt, size_t iv_len, size_t salt_len) {
    if (RAND_bytes(iv, iv_len) != 1) {
        return -1; // Ошибка генерации iv
    }
    if (RAND_bytes(salt, salt_len) != 1) {
        return -1; // Ошибка генерации соли
    }
    return 0;
}

/**
 * @brief Записывает iv и соль в указанный файл.
 * 
 * @param filename Имя файла для записи iv и соли.
 * @param iv Указатель на массив с iv.
 * @param salt Указатель на массив с солью.
 * @param iv_len Длина iv.
 * @param salt_len Длина соли.
 * @return int Возвращает 0 в случае успеха, иначе -1.
 */
int write_iv_and_salt_to_file(const char *filename, unsigned char *iv, unsigned char *salt, size_t iv_len, size_t salt_len) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        return -1; // Ошибка открытия файла
    }
    fwrite(iv, 1, iv_len, file);
    fwrite(salt, 1, salt_len, file);
    fclose(file);
    return 0;
}

/**
 * @brief Вырабатывает имитовставку (MAC) на основе заданного файла и пароля.
 * 
 * @param filename Имя файла для генерации имитовставки.
 * @param password Пароль для генерации ключа.
 * @param iv Вектор инициализации.
 * @param salt Соль.
 * @return int Возвращает 0 в случае успеха, иначе -1.
 */
int generate_mac(const char *filename, const char *password, unsigned char *iv, unsigned char *salt) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        return -1; // Ошибка открытия файла
    }

    // Определяем ключ на основе пароля, iv и соли
    unsigned char key[EVP_MAX_KEY_LENGTH];
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, 16, 10000, EVP_sha256(), sizeof(key), key) == 0) {
        fclose(file);
        return -1; // Ошибка генерации ключа
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(file);
        return -1; // Ошибка создания контекста
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        return -1; // Ошибка инициализации шифрования
    }

    unsigned char buffer[1024];
    int len;
    unsigned char mac[EVP_GCM_TLS_TAG_LEN];

    while ((len = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, buffer, len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(file);
            return -1; // Ошибка обновления шифрования
        }
    }

    if (EVP_EncryptFinal_ex(ctx, NULL, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        return -1; // Ошибка завершения шифрования
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVP_GCM_TLS_TAG_LEN, mac) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        return -1; // Ошибка получения тега
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(file);

    // Записываем имитовставку в конец файла
    FILE *output_file = fopen("file+mac.txt", "ab");
    if (!output_file) {
        return -1; // Ошибка открытия файла
    }
    fwrite(mac, 1, EVP_GCM_TLS_TAG_LEN, output_file);
    fclose(output_file);

    return 0;
}

/**
 * @brief Основная функция программы.
 * 
 * @param argc Аргумент командной строки.
 * @param argv Массив аргументов командной строки.
 * @return int Код возврата программы.
 */
int main(int argc, char *argv[]) {
    int opt;
    const char *filename = NULL;
    const char *password = NULL;
    const char *iv_salt_file = NULL;

    // Обработка аргументов командной строки
    while ((opt = getopt(argc, argv, "f:p:o:")) != -1) {
        switch (opt) {
            case 'f':
                filename = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'o':
                iv_salt_file = optarg;
                break;
            default:
                print_usage();
                return EXIT_FAILURE;
        }
    }

    // Проверка обязательных аргументов
    if (!filename || !password) {
        print_usage();
        return EXIT_FAILURE;
    }

    unsigned char iv[16];   // Длина iv для AES
    unsigned char salt[16]; // Длина соли

    // Генерация iv и соли, если не указан файл
    if (!iv_salt_file) {
        if (generate_iv_and_salt(iv, salt, sizeof(iv), sizeof(salt)) != 0) {
            fprintf(stderr, "Ошибка генерации iv и соли\n");
            return EXIT_FAILURE;
        }
        if (write_iv_and_salt_to_file("iv_salt.txt", iv, salt, sizeof(iv), sizeof(salt)) != 0) {
            fprintf(stderr, "Ошибка записи iv и соли в файл\n");
            return EXIT_FAILURE;
        }
    } else {
        // Чтение iv и соли из файла
        FILE *file = fopen(iv_salt_file, "r");
        if (!file) {
            fprintf(stderr, "Ошибка открытия файла iv и соли\n");
            return EXIT_FAILURE;
        }
        fread(iv, 1, sizeof(iv), file);
        fread(salt, 1, sizeof(salt), file);
        fclose(file);
    }

    // Генерация имитовставки
    if (generate_mac(filename, password, iv, salt) != 0) {
        fprintf(stderr, "Ошибка генерации имитовставки\n");
        return EXIT_FAILURE;
    }

    printf("Имитовставка успешно сгенерирована и записана в файл 'file+mac.txt'\n");
    return EXIT_SUCCESS;
}
