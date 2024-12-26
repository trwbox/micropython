# CMake file for VCC-GND YD-RP2040 boards

# The YD-RP2040 board doesn't have official pico-sdk support so we define it
list(APPEND PICO_BOARD_HEADER_DIRS ${MICROPY_BOARD_DIR})

# Freeze board.py
set(MICROPY_FROZEN_MANIFEST ${MICROPY_BOARD_DIR}/manifest.py)
