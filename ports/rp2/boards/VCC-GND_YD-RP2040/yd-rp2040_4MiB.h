// A pico-sdk board definition is required since the WeAct Studio boards are
// not officially supported.
//
// Officially supported boards:
//     https://github.com/raspberrypi/pico-sdk/tree/master/src/boards/include/boards

#ifndef _BOARDS_YDRP2040_4MB_H
#define _BOARDS_YDRP2040_4MB_H

#include "yd-rp2040_common.h"

#define YDRP2040_4MB

#ifndef PICO_FLASH_SIZE_BYTES
#define PICO_FLASH_SIZE_BYTES (4 * 1024 * 1024)
#endif

#endif
