#define MICROPY_HW_BOARD_NAME "VCC-GND YD-2040"

#define MICROPY_HW_USB_VID (0x2e8A)
#define MICROPY_HW_USB_PID (0x102e)

// Allow 1MB for the firmware image itself, allocate the remainder to the filesystem
#define MICROPY_HW_FLASH_STORAGE_BYTES (PICO_FLASH_SIZE_BYTES - (1 * 1024 * 1024))