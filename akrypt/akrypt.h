/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл akrypt.c                                                                                  */
/*  - содержит объявления служебных функций консольного клиента                                    */
/* ----------------------------------------------------------------------------------------------- */
 #ifndef AKRYPT_H
 #define AKRYPT_H

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>
 #include <getopt.h>
 #ifdef _WIN32
  #include <windows.h>
  #include <tchar.h>
 #else
  #define TCHAR char
 #endif

/* ----------------------------------------------------------------------------------------------- */
 #ifdef LIBAKRYPT_HAVE_SYSSTAT_H
  #include <sys/stat.h>
 #endif
 #ifdef LIBAKRYPT_HAVE_UNISTD_H
  #include <unistd.h>
 #endif
 #ifdef LIBAKRYPT_HAVE_DIRENT_H
  #include <dirent.h>
 #endif
 #ifdef LIBAKRYPT_HAVE_ERRNO_H
  #include <errno.h>
 #endif
 #ifdef LIBAKRYPT_HAVE_FNMATCH_H
  #include <fnmatch.h>
 #endif
 #ifdef LIBAKRYPT_HAVE_FCNTL_H
  #include <fcntl.h>
 #endif
 #ifdef LIBAKRYPT_HAVE_LOCALE_H
  #include <locale.h>
 #endif
 #ifdef LIBAKRYPT_HAVE_LIBINTL_H
  #include <libintl.h>
  #define _( string ) gettext( string )
 #else
  #define _( string ) ( string )
 #endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef _MSC_VER
 #define	S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
 #define	S_ISREG(mode)  (((mode) & S_IFMT) == S_IFREG)
#endif
#ifndef DT_DIR
 #define DT_DIR (4)
#endif
#ifndef DT_REG
 #define DT_REG (8)
#endif

/* ----------------------------------------------------------------------------------------------- */
 #define akrypt_max_icode_size  (128)

/* ----------------------------------------------------------------------------------------------- */
 extern ak_function_log *audit;
 extern char audit_filename[1024];

/* ----------------------------------------------------------------------------------------------- */
/* определение функции для выполнения действий с заданным файлом */
 typedef int ( ak_function_find )( const TCHAR * , ak_pointer );
/* определение функции, передаваемой в качестве аргумента в функцию построчного чтения файлов. */
 typedef int ( ak_file_read_function ) ( char * , ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/* обход каталога с учетом заданной маски */
 int akrypt_find( const TCHAR *, const TCHAR *, ak_function_find *, ak_pointer , bool_t );
/* проверка, является ли заданная стирока файлом или директорией */
 int akrypt_file_or_directory( const TCHAR * );

/* ----------------------------------------------------------------------------------------------- */
/* вывод очень короткой справки о программе */
 int akrypt_litehelp( void );
/* вывод длинной справки о программе */
 int akrypt_help( void );
/* проверка корректности заданной пользователем команды */
 bool_t akrypt_check_command( const char *, TCHAR * );
/* вывод сообщений в заданный пользователем файл, а также в стандартный демон вывода сообщений */
 int akrypt_audit_function( const char * );
/* определение функции вывода сообщений о ходе выполнения программы */
 void akrypt_set_audit( TCHAR * );
/* построчное чтение файла и применение к каждой строке заданной функции */
 int ak_file_read_by_lines( const char * , ak_file_read_function * , ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/* реализации пользовательских команд */
 int akrypt_hash( int argc, TCHAR *argv[] );
 int akrypt_show( int argc, TCHAR *argv[] );

 #endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       akrypt.h  */
/* ----------------------------------------------------------------------------------------------- */
