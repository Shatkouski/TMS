#!/bin/bash

# Установка необходимых инструментов
echo "Установка AVML..."
sudo apt-get install -y avml

echo "Установка Volatility..."
sudo apt-get install -y volatility

echo "Установка dwarf2json..."
sudo apt-get install -y dwarf2json

# Создание дампа оперативной памяти с помощью AVML
echo "Создание дампа оперативной памяти..."
sudo avml -o dump.raw

# Запуск Volatility для работы с артефактами форензики
echo "Запуск Volatility..."
sudo volatility -f dump.raw --profile=Linux --dump-dir=/tmp/volatility

# Создание symbol table для кастомного ядра Linux с помощью dwarf2json
echo "Создание symbol table..."
sudo dwarf2json -o symbol_table.json /path/to/custom/kernel/vmlinux

# Сделать снимок Debug kernel для symbol table
echo "Сделать снимок Debug kernel..."
sudo gdb -ex "set logging file debug_kernel.log" -ex "set logging on" -ex "target remote :1234" -ex "continue" /path/to/custom/kernel/vmlinux

