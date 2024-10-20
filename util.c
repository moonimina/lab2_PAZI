#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <getopt.h>

/**
 * @brief Функция для генерации ключа из пароля с использованием PBKDF2.
 * 
 * @param password Пароль.
 * @param salt Соль.
 * @param key Буфер для сохранения ключа.
 * @param key_len Длина ключа.
 * @param iterations Количество итераций для PBKDF2.
 * @return int 0 в случае успеха, иначе 1.
 */
int derive_key(const char *password, const unsigned char *salt, unsigned char *key, int key_len, int iterations) {
    if (PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), salt, 16, iterations, key_len, key) != 1) {
        fprintf(stderr, "Ошибка при генерации ключа.\n");
        return 1;
    }
    return 0;
}

/**
 * @brief Функция для выработки имитовставки GMAC на основе файла и ключа.
 * 
 * @param file_name Имя файла для вычисления имитовставки.
 * @param key Ключ для GMAC.
 * @param key_len Длина ключа.
 * @param mac Буфер для хранения имитовставки.
 * @param mac_len Длина имитовставки.
 * @return int 0 в случае успеха, иначе 1.
 */
int generate_gmac(const char *file_name, const unsigned char *key, int key_len, unsigned char *mac, unsigned int *mac_len) {
    FILE *file = fopen(file_name, "rb");
    if (!file) {
        perror("Не удалось открыть файл");
        return 1;
    }

    EVP_CIPHER_CTX *ctx;
    unsigned char iv[12];  // Используем IV длиной 12 байт (рекомендовано для GCM/GMAC)
    unsigned char buffer[1024];
    size_t bytes_read;

    // Генерация случайного IV
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        fprintf(stderr, "Ошибка генерации IV.\n");
        fclose(file);
        return 1;
    }

    // Инициализация контекста для GMAC
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Ошибка создания контекста.\n");
        fclose(file);
        return 1;
    }

    // Инициализация шифра для GCM (без шифрования, только MAC)
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Ошибка инициализации шифра.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        return 1;
    }

    // Установка ключа и IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        fprintf(stderr, "Ошибка установки ключа и IV.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        return 1;
    }

    // Чтение файла и обновление GMAC
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, (int*)&bytes_read, buffer, (int)bytes_read) != 1) {
            fprintf(stderr, "Ошибка обновления GMAC.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(file);
            return 1;
        }
    }

    if (ferror(file)) {
        perror("Ошибка чтения файла");
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        return 1;
    }

    // Завершение выработки имитовставки
    if (EVP_EncryptFinal_ex(ctx, NULL, (int*)&bytes_read) != 1) {
        fprintf(stderr, "Ошибка завершения GMAC.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        return 1;
    }

    // Получение значения имитовставки
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, mac) != 1) {
        fprintf(stderr, "Ошибка получения имитовставки.\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        return 1;
    }

    *mac_len = 16; // Длина имитовставки для GMAC (16 байт)

    EVP_CIPHER_CTX_free(ctx);
    fclose(file);
    return 0;
}

/**
 * @brief Основная функция программы. Обрабатывает аргументы командной строки и выполняет выработку имитовставки.
 * 
 * @param argc Количество аргументов.
 * @param argv Массив аргументов.
 * @return int 0 в случае успеха, иначе 1.
 */
int main(int argc, char *argv[]) {
    char *file_name = NULL;
    char *password = NULL;
    unsigned char key[32];  // Ключ для AES-256
    unsigned char salt[16]; // Соль для PBKDF2
    unsigned char mac[16];  // Буфер для имитовставки
    unsigned int mac_len;
    int iterations = 10000; // Количество итераций для PBKDF2
    int opt;

    // Генерация соли
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        fprintf(stderr, "Ошибка генерации соли.\n");
        return 1;
    }

    // Обработка аргументов командной строки
    while ((opt = getopt(argc, argv, "f:p:")) != -1) {
        switch (opt) {
            case 'f':
                file_name = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            default:
                fprintf(stderr, "Использование: %s -f <имя файла> -p <пароль>\n", argv[0]);
                return 1;
        }
    }

    if (!file_name || !password) {
        fprintf(stderr, "Необходимо указать файл и пароль.\n");
        fprintf(stderr, "Использование: %s -f <имя файла> -p <пароль>\n", argv[0]);
        return 1;
    }

    // Генерация ключа из пароля
    if (derive_key(password, salt, key, sizeof(key), iterations) != 0) {
        return 1;
    }

    // Выработка имитовставки GMAC
    if (generate_gmac(file_name, key, sizeof(key), mac, &mac_len) != 0) {
        return 1;
    }

    // Вывод результата
    printf("Имитовставка (GMAC): ");
    for (unsigned int i = 0; i < mac_len; i++) {
        printf("%02x", mac[i]);
    }
    printf("\n");

    return 0;
}
