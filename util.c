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
    printf("Использование: ./gmac_util -f <файл> -p <пароль> [-i <iv и соль файл>]\n");
    printf("Опции:\n");
    printf("  -f <файл>          Путь к файлу, для которого будет генерироваться имитовставка.\n");
    printf("  -p <пароль>        Пароль для генерации ключа.\n");
    printf("  -i <iv и соль файл> Путь к файлу с IV и солью, разделенными пробелом (опционально).\n");
    printf("\nНажмите Enter для продолжения...\n");
    getchar(); // Ожидание ввода
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
        perror("Не удалось открыть файл для чтения");
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
 * @brief Выводит имитовставку на консоль.
 * @param mac Указатель на имитовставку.
 * @param mac_len Длина имитовставки.
 */
void print_mac(const unsigned char *mac, unsigned int mac_len) {
    printf("Имитовставка (MAC): ");
    for (unsigned int i = 0; i < mac_len; i++) {
        printf("%02x", mac[i]);
    }
    printf("\n");
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
    char *iv_salt_file = NULL;

    // Обработка аргументов командной строки
    int opt;
    while ((opt = getopt(argc, argv, "f:p:i:")) != -1) {
        switch (opt) {
            case 'f':
                filename = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'i':
                iv_salt_file = optarg;
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

    unsigned char iv[16];
    unsigned char salt[16];

    // Чтение IV и соли из файла, если указан
    if (iv_salt_file != NULL) {
        FILE *iv_salt_fp = fopen(iv_salt_file, "r");
        if (!iv_salt_fp) {
            perror("Не удалось открыть файл IV и соли");
            return EXIT_FAILURE;
        }

        // Чтение IV и соли из файла
        if (fscanf(iv_salt_fp, "%16s %16s", iv, salt) != 2) {
            fprintf(stderr, "Ошибка при чтении IV и соли из файла\n");
            fclose(iv_salt_fp);
            return EXIT_FAILURE;
        }

        fclose(iv_salt_fp);
    } else {
        // Генерация случайного IV и соли
        if (RAND_bytes(iv, sizeof(iv)) != 1) {
            fprintf(stderr, "Ошибка генерации IV\n");
            return EXIT_FAILURE;
        }
        if (RAND_bytes(salt, sizeof(salt)) != 1) {
            fprintf(stderr, "Ошибка генерации соли\n");
            return EXIT_FAILURE;
        }

        // Запись IV и соли в файл
        FILE *iv_salt_fp = fopen("iv_salt.txt", "w");
        if (!iv_salt_fp) {
            perror("Не удалось создать файл для записи IV и соли");
            return EXIT_FAILURE;
        }
        fprintf(iv_salt_fp, "%s %s\n", iv, salt);
        fclose(iv_salt_fp);
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

    // Вывод имитовставки на консоль
    print_mac(mac, EVP_MAX_MD_SIZE);

    free(mac);
    return EXIT_SUCCESS;
}
