#include <iostream>
#include <fstream>
#include <random>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <dirent.h>

// Para compilarlo correctamente se debe ejecutar:
//g++ nombreDelEncoder.cpp -o nombreDelEncoder -lssl -lcrypto

// Declaraciones de funciones
/**
 * Genera una cadena aleatoria de longitud dada.
 * @param length Longitud de la cadena aleatoria (por defecto: 8).
 * @return Cadena aleatoria generada.
 */
std::string random_string(int length = 8);

/**
 * Lee el contenido de un archivo y lo devuelve como una cadena.
 * @param file_path Ruta del archivo a leer.
 * @return Contenido del archivo como una cadena.
 */
std::string read_file(const std::string &file_path);

/**
 * Codifica los datos en base64.
 * @param data Datos a codificar.
 * @return Datos codificados en base64.
 */
std::string base64_encode(const std::string &data);

/**
 * Genera un script PHP que ejecuta el código codificado con base64.
 * @param base64_encoded Código PHP codificado en base64.
 * @return Script PHP generado.
 */
std::string generate_encoded_php(const std::string &base64_encoded);

/**
 * Escribe el código PHP codificado en un nuevo archivo.
 * @param php_code Código PHP codificado.
 * @param file_path Ruta del archivo original.
 * @param repetitions Número de repeticiones.
 * @param iteration Iteración actual.
 * @return Ruta del archivo donde se ha escrito el código.
 */
std::string write_encoded_php(const std::string &php_code, const std::string &file_path, int repetitions, int iteration);

/**
 * Elimina archivos intermedios generados en iteraciones anteriores.
 * @param file_path Ruta del archivo original.
 * @param repetitions Número de repeticiones.
 * @param current_iteration Iteración actual.
 */
void delete_previous_files(const std::string &file_path, int repetitions, int current_iteration);

/**
 * Guarda el código PHP codificado en un archivo final.
 * @param encoded_php Código PHP codificado.
 * @param file_path Ruta del archivo original.
 * @param repetitions Número de repeticiones.
 * @return Ruta del archivo donde se ha guardado el código final.
 */
std::string save_final_encoded_php(const std::string &encoded_php, const std::string &file_path, int repetitions);

/**
 * Obtiene un nombre de archivo único.
 * @param file_path Ruta base del archivo.
 * @return Nombre de archivo único.
 */
std::string get_unique_file_name(const std::string &file_path);

/**
 * Renombra un archivo.
 * @param old_file_path Ruta del archivo original.
 * @param new_file_path Nueva ruta del archivo.
 */
void rename_file(const std::string &old_file_path, const std::string &new_file_path);

/**
 * Genera el hash MD5 del archivo especificado.
 * @param file_path Ruta del archivo.
 * @return Hash MD5 del archivo.
 */
std::string generate_md5(const std::string &file_path);

/**
 * Obtiene la lista de archivos que contienen la terminación _encodeado_final.php.
 * @return Vector de nombres de archivos.
 */
std::vector<std::string> get_encoded_final_files();

/**
 * Muestra los MD5 de los archivos codificados finales.
 */
void display_md5_of_encoded_files();

/**
 * Codifica un archivo PHP con base64 y lo guarda en un nuevo archivo.
 * @param file_path Ruta del archivo PHP a codificar.
 * @param repetitions Número de repeticiones de codificación (por defecto: 1).
 */
void encode_php(const std::string &file_path, int repetitions = 1);

// Funciones auxiliares

/**
 * Genera una cadena aleatoria de longitud dada.
 */
std::string random_string(int length)
{
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    std::string result;
    result.reserve(length);
    for (int i = 0; i < length; ++i)
    {
        result += alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    return result;
}

/**
 * Lee el contenido de un archivo y lo devuelve como una cadena.
 */
std::string read_file(const std::string &file_path)
{
    std::ifstream file(file_path);
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

/**
 * Codifica los datos en base64.
 */
std::string base64_encode(const std::string &data)
{
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string encoded;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (unsigned char c : data)
    {
        char_array_3[i++] = c;
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
            {
                encoded += base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
        {
            char_array_3[j] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; j < i + 1; j++)
        {
            encoded += base64_chars[char_array_4[j]];
        }

        while (i++ < 3)
        {
            encoded += '=';
        }
    }

    return encoded;
}

/**
 * Genera un script PHP que ejecuta el código codificado con base64.
 */
std::string generate_encoded_php(const std::string &base64_encoded)
{
    return R"(<?php
    $encoded_code = ")" +
           base64_encoded + R"(";
    $decoded_code = base64_decode($encoded_code);
    eval("?>" . $decoded_code);
    ?>)";
}

/**
 * Escribe el código PHP codificado en un nuevo archivo.
 */
std::string write_encoded_php(const std::string &php_code, const std::string &file_path, int repetitions, int iteration)
{
    std::string output_file_path = file_path;
    size_t pos = output_file_path.find(".php");
    if (pos != std::string::npos)
    {
        output_file_path.replace(pos, 4, "_encodeado_" + std::to_string(iteration) + "_de_" + std::to_string(repetitions) + "_veces.php");
    }
    std::ofstream output_file(output_file_path);
    output_file << php_code;
    return output_file_path;
}

/**
 * Elimina archivos intermedios generados en iteraciones anteriores.
 */
void delete_previous_files(const std::string &file_path, int repetitions, int current_iteration)
{
    if (current_iteration > 0)
    {
        for (int i = 1; i < current_iteration; ++i)
        {
            std::string previous_file_path = file_path;
            size_t pos = previous_file_path.find(".php");
            if (pos != std::string::npos)
            {
                previous_file_path.replace(pos, 4, "_encodeado_" + std::to_string(i) + "_de_" + std::to_string(repetitions) + "_veces.php");
                if (access(previous_file_path.c_str(), F_OK) == 0)
                {
                    remove(previous_file_path.c_str());
                }
            }
        }
    }
}

/**
 * Guarda el código PHP codificado en un archivo final.
 */
std::string save_final_encoded_php(const std::string &encoded_php, const std::string &file_path, int repetitions)
{
    std::string php_code = R"(<?php
$encoded_code = ")" + encoded_php +
                           R"(";
$decoded_code = base64_decode($encoded_code);
eval("?>" . $decoded_code);
?>)";
    std::string output_file_path = file_path;
    size_t pos = output_file_path.find(".php");
    if (pos != std::string::npos)
    {
        output_file_path.replace(pos, 4, "_encodeado_final.php");
        output_file_path = get_unique_file_name(output_file_path);
        std::ofstream output_file(output_file_path);
        output_file << php_code;
        output_file.close();
    }
    return output_file_path;
}

/**
 * Obtiene un nombre de archivo único.
 */
std::string get_unique_file_name(const std::string &file_path)
{
    if (access(file_path.c_str(), F_OK) != 0)
    {
        return file_path;
    }
    int i = 1;
    while (true)
    {
        std::string new_file_path = file_path;
        size_t pos = new_file_path.find(".php");
        if (pos != std::string::npos)
        {
            new_file_path.replace(pos, 4, "_" + std::to_string(i) + ".php");
            if (access(new_file_path.c_str(), F_OK) != 0)
            {
                return new_file_path;
            }
            ++i;
        }
    }
    return file_path;
}

/**
 * Renombra un archivo.
 */
void rename_file(const std::string &old_file_path, const std::string &new_file_path)
{
    rename(old_file_path.c_str(), new_file_path.c_str());
}

/**
 * Genera el hash MD5 del archivo especificado.
 */
std::string generate_md5(const std::string &file_path)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();

    EVP_DigestInit_ex(ctx, md, NULL);

    char buffer[1024];
    std::ifstream file(file_path, std::ios::binary);
    while (file.read(buffer, sizeof(buffer)))
    {
        EVP_DigestUpdate(ctx, buffer, file.gcount());
    }
    EVP_DigestUpdate(ctx, buffer, file.gcount()); // para la última parte del archivo

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    EVP_DigestFinal_ex(ctx, md_value, &md_len);

    EVP_MD_CTX_free(ctx);

    std::ostringstream md5_string;
    for (unsigned int i = 0; i < md_len; ++i)
    {
        md5_string << std::hex << std::setw(2) << std::setfill('0') << (int)md_value[i];
    }

    return md5_string.str();
}

/**
 * Obtiene una lista de archivos finales codificados.
 */
std::vector<std::string> get_encoded_final_files()
{
    std::vector<std::string> encoded_final_files;
    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir(".")) != NULL)
    {
        while ((ent = readdir(dir)) != NULL)
        {
            std::string file_name = ent->d_name;
            if (file_name.find("_encodeado_final.php") != std::string::npos)
            {
                encoded_final_files.push_back(file_name);
            }
        }
        closedir(dir);
    }
    return encoded_final_files;
}

/**
 * Muestra los hashes MD5 de los archivos codificados finales.
 */
void display_md5_of_encoded_files()
{
    std::vector<std::string> encoded_files = get_encoded_final_files();
    for (const std::string &file_path : encoded_files)
    {
        std::string md5_hash = generate_md5(file_path);
        std::cout << "Archivo: " << file_path << " - MD5: " << md5_hash << std::endl;
    }
}

/**
 * Codifica el archivo PHP especificado.
 */
void encode_php(const std::string &file_path, int repetitions)
{
    std::string original_php_code = read_file(file_path);
    std::string encoded_php = base64_encode(original_php_code);

    delete_previous_files(file_path, repetitions, 0);
    std::string final_encoded_php = save_final_encoded_php(encoded_php, file_path, repetitions);
    std::cout << "PHP encodeado guardado en: " << final_encoded_php << std::endl;
}

/**
 * Función principal.
 * @param argc Número de argumentos de línea de comandos.
 * @param argv Argumentos de línea de comandos.
 * @return 0 si la ejecución fue exitosa, 1 en caso contrario.
 */
int main(int argc, char *argv[])
{
    srand(time(nullptr));
    if (argc < 2)
    {
        std::cerr << "Uso: " << argv[0] << " <ruta_del_archivo_php> [repeticiones]" << std::endl;
        return 1;
    }

    std::string file_path = argv[1];
    int repetitions = (argc >= 3) ? std::stoi(argv[2]) : 1;

    encode_php(file_path, repetitions);
    display_md5_of_encoded_files();

    return 0;
}
