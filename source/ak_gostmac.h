/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_gostmac.h                                                                              */
/*  - содержит описания функций, реализующих алгоритм выработки имитовставки ГОСТ Р 34.13-2015.    */
/* ----------------------------------------------------------------------------------------------- */
#ifndef __AK_GOSTMAC_H__
#define __AK_GOSTMAC_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_bckey.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Секретный ключ алгоритма выработки имитовставки ГОСТ Р 34.13-2015. */
/*!  Алгоритм выработки имитовставки ГОСТ Р 34.13-2015 представляет собой адаптацию алгоритма OMAC
     для отечественных алгоритмов блоного шифрования Магма и Кузнечик.                             */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct gostmac {
 /*! \brief Контекст секретного ключа алгоритма блочного шифрования. */
  struct bckey bkey;
 /*! \brief Вектор с промежуточным значением имитовставки. */
  struct buffer imito;
} *ak_hmac;


