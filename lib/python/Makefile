include ../../config.mk

# Set DESTDIR if it isn't given
DESTDIR?=/

.PHONY : all clean install

ifeq ($(WITH_PYTHON),yes)
all : mosquitto.pyc
else
all :
endif

ifeq ($(WITH_PYTHON),yes)
install : all

else
install :
endif

mosquitto.pyc : mosquitto.py


clean :
	-rm -rf build mosquitto.pyc __pycache__
