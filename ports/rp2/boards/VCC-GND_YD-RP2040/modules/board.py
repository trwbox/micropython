from machine import Pin, Signal

LED = Pin("LED", Pin.OUT, value=0)
USR_KEY = Pin("USR_KEY", Pin.IN, Pin.PULL_UP)
NEOPIXEL = Pin("NEOPIXEL", Pin.OUT, value=0)

del Pin