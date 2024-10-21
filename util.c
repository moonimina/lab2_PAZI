#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>

#define SALT_SIZE 16   ///< Размер соли в байтах
#define IV_SIZE 12     ///< Размер IV в байтах
#define MAC_SIZE 16    ///< Размер имитовставки (GMAC) в байтах

/// @brief Функция для выработки ключа на основе пароля, соли и алгоритма PBKDF2
/// @param password Пароль
/// @param salt Соль
/// @param key Буфер для хранения выработанного ключа
/// @param key_len Длина ключа
/// @return 0 в случае успеха, -1 в случае ошибки
int derive_key(const char *password, const unsigned char *salt, unsigned char *key, int key_len) {
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, 10000, EVP_sha256(), key_len, key)) {
        fprintf(stderr, "Ошибка выработки ключа\n");
        return -1;
    }
    return 0;
}

/// @brief Функция для записи данных в файл
/// @param filename Имя файла
/// @param data Данные для записи
/// @param len Размер данных
/// @return 0 в случае успеха, -1 в случае ошибки
int write_to_file(const char *filename, const unsigned char *data, size_t len) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Не удалось открыть файл для записи");
        return -1;
    }
    fwrite(data, 1, len, file);
    fclose(file);
    return 0;
}

/// @brief Функция для копирования данных из одного файла в другой
/// @param src_filename Имя исходного файла
/// @param dst_filename Имя целевого файла
/// @return 0 в случае успеха, -1 в случае ошибки
int copy_file(const char *src_filename, const char *dst_filename) {
    FILE *src_file = fopen(src_filename, "rb");
    if (!src_file) {
        perror("Не удалось открыть исходный файл для чтения");
        return -1;
    }

    FILE *dst_file = fopen(dst_filename, "wb");
    if (!dst_file) {
        perror("Не удалось открыть целевой файл для записи");
        fclose(src_file);
        return -1;
    }

    char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), src_file)) > 0) {
        fwrite(buffer, 1, bytes_read, dst_file);
    }

    fclose(src_file);
    fclose(dst_file);
    return 0;
}

/// @brief Функция для записи данных в конец файла
/// @param filename Имя файла
/// @param data Данные для записи
/// @param len Размер данных
/// @return 0 в случае успеха, -1 в случае ошибки
int append_to_file(const char *filename, const unsigned char *data, size_t len) {
    FILE *file = fopen(filename, "ab");
    if (!file) {
        perror("Не удалось открыть файл для добавления данных");
        return -1;
    }
    fwrite(data, 1, len, file);
    fclose(file);
    return 0;
}

/// @brief Функция для чтения данных из файла
/// @param filename Имя файла
/// @param data Буфер для хранения данных
/// @param len Размер буфера
/// @return Количество прочитанных байт, либо -1 в случае ошибки
int read_from_file(const char *filename, unsigned char *data, size_t len) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Не удалось открыть файл для чтения");
        return -1;
    }
    size_t read_len = fread(data, 1, len, file);
    fclose(file);
    return (int)read_len;
}

/// @brief Функция для выработки и сохранения имитовставки (GMAC)
/// @param filename Имя файла для чтения данных
/// @param password Пароль для выработки ключа
/// @param salt Соль
/// @param iv IV (инициализационный вектор)
/// @param mac Буфер для хранения выработанной имитовставки
/// @return 0 в случае успеха, -1 в случае ошибки
int generate_mac(const char *filename, const char *password, unsigned char *salt, unsigned char *iv, unsigned char *mac) {
    unsigned char key[32];
    
    // Выработка ключа из пароля и соли
    if (derive_key(password, salt, key, sizeof(key)) != 0)
        return -1;

    // Чтение данных файла
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Не удалось открыть файл");
        return -1;
    }
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    unsigned char *file_data = malloc(file_size);
    if (fread(file_data, 1, file_size, file) != file_size) {
        perror("Ошибка чтения файла");
        fclose(file);
        free(file_data);
        return -1;
    }
    fclose(file);

    // Настройка контекста шифрования
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("Ошибка создания контекста шифрования");
        free(file_data);
        return -1;
    }

    // Инициализация контекста с использованием AES-256 в режиме GMAC
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        perror("Ошибка инициализации шифра");
        free(file_data);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        perror("Ошибка установки ключа и IV");
        free(file_data);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Обработка файла
    int len;
    if (!EVP_EncryptUpdate(ctx, NULL, &len, file_data, file_size)) {
        perror("Ошибка обработки данных");
        free(file_data);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Получение имитовставки (GMAC)
    if (!EVP_EncryptFinal_ex(ctx, NULL, &len)) {
        perror("Ошибка завершения шифрования");
        free(file_data);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MAC_SIZE, mac)) {
        perror("Ошибка получения имитовставки");
        free(file_data);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Освобождение памяти
    free(file_data);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

/// @brief Функция для проверки имитовставки
/// @param filename Имя файла
/// @param password Пароль для выработки ключа
/// @param salt Соль
/// @param iv IV (инициализационный вектор)
/// @param mac Имитовставка для проверки
/// @return 0, если проверка успешна, -1 в случае ошибки
int verify_mac(const char *filename, const char *password, unsigned char *salt, unsigned char *iv, unsigned char *mac) {
    unsigned char calculated_mac[MAC_SIZE];

    // Генерация имитовставки
    if (generate_mac(filename, password, salt, iv, calculated_mac) != 0) {
        return -1;
    }

    // Сравнение имитовставок
    if (memcmp(mac, calculated_mac, MAC_SIZE) != 0) {
        fprintf(stderr, "Имитовставка не совпадает!\n");
        return -1;
    }

    printf("Имитовставка успешно проверена!\n");
    return 0;
}

/// @brief Основная функция программы
/// @param argc Количество аргументов командной строки
/// @param argv Аргументы командной строки
/// @return 0 в случае успеха, -1 в случае ошибки
int main(int argc, char *argv[]) {
    int s_flag = 0;
    char *password = NULL;
    char *filename = NULL;

    // Обработка аргументов командной строки
    int opt;
    while ((opt = getopt(argc, argv, "sp:f:")) != -1) {
        switch (opt) {
        case 's':
            s_flag = 1; // Генерация имитовставки
            break;
        case 'p':
            password = optarg; // Пароль
            break;
        case 'f':
            filename = optarg; // Имя файла
            break;
        default:
            fprintf(stderr, "Usage: %s [-s] -p password -f filename\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (!password || !filename) {
        fprintf(stderr, "Пароль и имя файла обязательны!\n");
        exit(EXIT_FAILURE);
    }

    unsigned char salt[SALT_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char mac[MAC_SIZE];

    if (s_flag) {
        // Генерация соли и IV
        if (!RAND_bytes(salt, SALT_SIZE) || !RAND_bytes(iv, IV_SIZE)) {
            perror("Ошибка генерации соли или IV");
            exit(EXIT_FAILURE);
        }

        // Генерация имитовставки
        if (generate_mac(filename, password, salt, iv, mac) != 0) {
            exit(EXIT_FAILURE);
        }

        // Сохранение соли, IV и имитовставки в файл
        write_to_file("salt.bin", salt, SALT_SIZE);
        write_to_file("iv.bin", iv, IV_SIZE);

        // Копирование исходного файла и добавление в конец имитовставки
        char new_filename[256];
        snprintf(new_filename, sizeof(new_filename), "%s_mac.txt", filename);
        if (copy_file(filename, new_filename) != 0) {
            exit(EXIT_FAILURE);
        }

        // Добавление имитовставки в новый файл
        if (append_to_file(new_filename, mac, MAC_SIZE) != 0) {
            exit(EXIT_FAILURE);
        }

        printf("Файл с имитовставкой создан: %s\n", new_filename);
    } else {
        // Чтение соли и IV из файлов
        read_from_file("salt.bin", salt, SALT_SIZE);
        read_from_file("iv.bin", iv, IV_SIZE);

        // Чтение имитовставки для проверки
        read_from_file(filename, mac, MAC_SIZE);

        // Проверка имитовставки
        if (verify_mac(filename, password, salt, iv, mac) != 0) {
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}
