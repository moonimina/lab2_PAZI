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
    // Используется PBKDF2 для генерации ключа на основе пароля и соли
    if (PKCS5_PBKDF2_HMAC_SHA1(password, strlen(password), salt, 16, iterations, key_len, key) != 1) {
        fprintf(stderr, "Ошибка при генерации ключа.\n");
        return 1;
    }
    return 0;
}

/**
 * @brief Функция для выработки имитовставки GMAC на основе файла и ключа.
 * 
 * Использует AES-256-GCM для генерации имитовставки на основе содержимого файла.
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
 * @brief Функция для сохранения соли и IV в файлы.
 * 
 * Сохраняет соль и IV в файлы salt.bin и iv.bin для последующего использования.
 * 
 * @param salt Соль для сохранения.
 * @param iv IV для сохранения.
 * @return int 0 в случае успеха, иначе 1.
 */
int save_salt_iv(const unsigned char *salt, const unsigned char *iv) {
    FILE *salt_file = fopen("salt.bin", "wb");
    if (!salt_file) {
        perror("Не удалось открыть файл для сохранения соли");
        return 1;
    }
    if (fwrite(salt, 1, 16, salt_file) != 16) {
        perror("Ошибка записи соли в файл");
        fclose(salt_file);
        return 1;
    }
    fclose(salt_file);

    FILE *iv_file = fopen("iv.bin", "wb");
    if (!iv_file) {
        perror("Не удалось открыть файл для сохранения IV");
        return 1;
    }
    if (fwrite(iv, 1, 12, iv_file) != 12) {
        perror("Ошибка записи IV в файл");
        fclose(iv_file);
        return 1;
    }
    fclose(iv_file);

    return 0;
}
/**
 * @brief Функция для записи исходного файла с имитовставкой в новый файл.
 * 
 * Записывает содержимое исходного файла и имитовставку в новый файл 
 * с добавлением суффикса "+mac" к имени файла.
 * 
 * @param original_file Имя исходного файла.
 * @param mac Имитовставка для записи.
 * @param mac_len Длина имитовставки.
 * @return int 0 в случае успеха, иначе 1.
 */
int write_file_with_mac(const char *original_file, const unsigned char *mac, unsigned int mac_len) {
    // Создаем новое имя файла
    char new_file_name[256];
    snprintf(new_file_name, sizeof(new_file_name), "%s+mac.txt", original_file);
    
    FILE *new_file = fopen(new_file_name, "wb");
    if (!new_file) {
        perror("Не удалось открыть файл для записи с имитовставкой");
        return 1;
    }

    // Открываем оригинальный файл для чтения
    FILE *orig_file = fopen(original_file, "rb");
    if (!orig_file) {
        perror("Не удалось открыть оригинальный файл для чтения");
        fclose(new_file);
        return 1;
    }

    // Копируем содержимое оригинального файла в новый файл
    unsigned char buffer[1024];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), orig_file)) > 0) {
        fwrite(buffer, 1, bytes_read, new_file);
    }

    fclose(orig_file);

    // Записываем имитовставку в шестнадцатеричном формате
    for (unsigned int i = 0; i < mac_len; i++) {
        fprintf(new_file, "%02x", mac[i]); // Преобразование в шестнадцатеричный формат
    }
    fprintf(new_file, "\n"); // Добавление новой строки для удобства

    fclose(new_file);

    return 0;
}
/**
 * @brief Основная функция программы. Обрабатывает аргументы командной строки и выполняет выработку имитовставки.
 * 
 * Если программа запускается первый раз для генерации имитовставки, необходимо использовать флаг -s.
 * Если программа используется для проверки имитовставки, необходимо загрузить файлы salt.bin и iv.bin и не использовать флаг -s.
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
    unsigned char iv[12];   // IV для GMAC
    int iterations = 10000; // Количество итераций для PBKDF2
    int opt;

    // Обработка аргументов командной строки
    while ((opt = getopt(argc, argv, "f:p:s")) != -1) {
        switch (opt) {
            case 'f':
                file_name = optarg;  // Чтение имени файла
                break;
            case 'p':
                password = optarg;  // Чтение пароля
                break;
            case 's':
                // Флаг для генерации соли и IV, просто продолжаем
                break;
            default:
                fprintf(stderr, "Использование: %s -f <имя файла> -p <пароль> [-s для сохранения соли и IV]\n", argv[0]);
                return 1;
        }
    }

    if (!file_name || !password) {
        fprintf(stderr, "Необходимо указать файл и пароль.\n");
        fprintf(stderr, "Использование: %s -f <имя файла> -p <пароль> [-s для сохранения соли и IV]\n", argv[0]);
        return 1;
    }

    // Проверяем, указан ли флаг -s
    if (optind < argc && strcmp(argv[optind], "-s") == 0) {
        // Генерация соли и IV
        if (RAND_bytes(salt, sizeof(salt)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
            fprintf(stderr, "Ошибка генерации соли или IV.\n");
            return 1;
        }
        // Сохранение соли и IV
        if (save_salt_iv(salt, iv) != 0) {
            return 1;
        }
        printf("Соль и IV успешно сохранены.\n");
    } else {
        // Загрузка соли и IV
        FILE *salt_file = fopen("salt.bin", "rb");
        if (!salt_file) {
            fprintf(stderr, "Не удалось открыть файл salt.bin для чтения.\n");
            return 1;
        }
        if (fread(salt, 1, sizeof(salt), salt_file) != sizeof(salt)) {
            fprintf(stderr, "Ошибка чтения соли из файла.\n");
            fclose(salt_file);
            return 1;
        }
        fclose(salt_file);
        
        FILE *iv_file = fopen("iv.bin", "rb");
        if (!iv_file) {
            fprintf(stderr, "Не удалось открыть файл iv.bin для чтения.\n");
            return 1;
        }
        if (fread(iv, 1, sizeof(iv), iv_file) != sizeof(iv)) {
            fprintf(stderr, "Ошибка чтения IV из файла.\n");
            fclose(iv_file);
            return 1;
        }
        fclose(iv_file);
    }

    // Генерация ключа из пароля
    if (derive_key(password, salt, key, sizeof(key), iterations) != 0) {
        return 1;
    }

    // Выработка имитовставки GMAC
    if (generate_gmac(file_name, key, sizeof(key), mac, &mac_len) != 0) {
        return 1;
    }

    // Запись исходного файла с имитовставкой в новый файл
    if (write_file_with_mac(file_name, mac, mac_len) != 0) {
        return 1;
    }

    // Вывод результата
    printf("Имитовставка (GMAC): ");
    for (unsigned int i = 0; i < mac_len; i++) {
        printf("%02x", mac[i]);
    }
    printf("\n");

    // Очищение чувствительных данных
    memset(key, 0, sizeof(key));
    memset(salt, 0, sizeof(salt));
    memset(mac, 0, sizeof(mac));
    memset(iv, 0, sizeof(iv));

    return 0;
}
