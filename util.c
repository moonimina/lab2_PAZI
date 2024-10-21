#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/**
 * @brief Вывод справки по использованию программы.
 */
void print_usage() {
    printf("Использование: ./gmac_util -f <файл> -p <пароль> [-i <iv файл> -s <соль файл>]\n");
    printf("Опции:\n");
    printf("  -f <файл>    Путь к файлу, для которого будет генерироваться имитовставка.\n");
    printf("  -p <пароль>  Пароль для генерации ключа.\n");
    printf("  -i <iv файл> Путь к файлу с IV для проверки целостности (опционально).\n");
    printf("  -s <соль файл> Путь к файлу с солью для проверки целостности (опционально).\n");
}

/**
 * @brief Генерирует ключ из пароля с использованием PBKDF2.
 * @param password Указатель на пароль.
 * @param salt Указатель на соль.
 * @param salt_len Длина соли.
 * @param key Указатель на выходной ключ.
 * @param key_len Длина ключа.
 */
void derive_key(const char *password, const unsigned char *salt, int salt_len, unsigned char *key, int key_len) {
    // Использование PBKDF2 для генерации ключа
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, salt_len, 10000, EVP_sha256(), key_len, key);
}

/**
 * @brief Генерирует имитовставку для указанного файла.
 * @param filename Указатель на имя файла.
 * @param key Указатель на ключ.
 * @param key_len Длина ключа.
 * @return Указатель на имитовставку (malloc), или NULL в случае ошибки.
 */
unsigned char *generate_mac(const char *filename, const unsigned char *key, int key_len) {
    unsigned char *mac = malloc(EVP_MAX_MD_SIZE);
    unsigned int mac_len;

    // Открываем файл для чтения
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Не удалось открыть файл");
        free(mac);
        return NULL;
    }

    // Инициализация контекста GMAC
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(file);
        free(mac);
        return NULL;
    }

    // Установка контекста для GMAC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        free(mac);
        return NULL;
    }

    // Установка ключа
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        free(mac);
        return NULL;
    }

    // Чтение файла и обновление контекста
    unsigned char buffer[4096];
    int bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &mac_len, buffer, bytes_read) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(file);
            free(mac);
            return NULL;
        }
    }

    // Завершение и получение имитовставки
    if (EVP_EncryptFinal_ex(ctx, mac, &mac_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(file);
        free(mac);
        return NULL;
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(file);
    return mac;
}

/**
 * @brief Записывает имитовставку в конец файла.
 * @param original_file Указатель на имя оригинального файла.
 * @param mac Указатель на имитовставку.
 * @param mac_len Длина имитовставки.
 */
void write_mac_to_file(const char *original_file, const unsigned char *mac, int mac_len) {
    // Создание нового имени файла
    char new_filename[256];
    snprintf(new_filename, sizeof(new_filename), "%s+mac.txt", original_file);

    // Открытие нового файла для записи
    FILE *file = fopen(new_filename, "wb");
    if (!file) {
        perror("Не удалось создать файл с имитовставкой");
        return;
    }

    // Запись оригинального файла
    FILE *orig_file = fopen(original_file, "rb");
    if (!orig_file) {
        perror("Не удалось открыть оригинальный файл");
        fclose(file);
        return;
    }

    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), orig_file)) > 0) {
        fwrite(buffer, 1, bytes_read, file);
    }

    // Запись имитовставки
    fwrite(mac, 1, mac_len, file);

    fclose(orig_file);
    fclose(file);
    printf("Имитовставка записана в файл: %s\n", new_filename);
}

/**
 * @brief Главная функция программы.
 * @param argc Количество аргументов командной строки.
 * @param argv Указатель на массив аргументов командной строки.
 * @return Код завершения программы.
 */
int main(int argc, char *argv[]) {
    char *filename = NULL;
    char *password = NULL;
    char *iv_file = NULL;
    char *salt_file = NULL;

    // Обработка аргументов командной строки
    int opt;
    while ((opt = getopt(argc, argv, "f:p:i:s:")) != -1) {
        switch (opt) {
            case 'f':
                filename = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'i':
                iv_file = optarg;
                break;
            case 's':
                salt_file = optarg;
                break;
            default:
                print_usage();
                return EXIT_FAILURE;
        }
    }

    // Проверка обязательных параметров
    if (filename == NULL || password == NULL) {
        print_usage();
        return EXIT_FAILURE;
    }

    // Генерация соли (если требуется)
    unsigned char salt[16];
    if (salt_file != NULL) {
        FILE *salt_fp = fopen(salt_file, "rb");
        if (!salt_fp) {
            perror("Не удалось открыть файл соли");
            return EXIT_FAILURE;
        }
        fread(salt, 1, sizeof(salt), salt_fp);
        fclose(salt_fp);
    } else {
        // Генерация случайной соли
        RAND_bytes(salt, sizeof(salt));
    }

    // Генерация ключа из пароля
    unsigned char key[EVP_MAX_KEY_LENGTH];
    derive_key(password, salt, sizeof(salt), key, sizeof(key));

    // Генерация имитовставки
    unsigned char *mac = generate_mac(filename, key, sizeof(key));
    if (mac == NULL) {
        fprintf(stderr, "Ошибка при генерации имитовставки\n");
        return EXIT_FAILURE;
    }

    // Запись имитовставки в файл
    write_mac_to_file(filename, mac, EVP_MAX_MD_SIZE);

    free(mac);
    return EXIT_SUCCESS;
}
