# Diplom Project TeachMeSkills

- [Diplom Project TeachMeSkills](#diplom-project-teachmeskills)
  * [Расследование инцидентов](#------------------------)
  * [Создать скрипт на любом языке, который в информативном виде будет запускать скрипт с установкой:](#------------------------------------------------------------------------------------------------)
  * [Автоматизировать процесс проверки url через virustotal](#----------------------------------url-------virustotal)
  * [Вы обнаружили уязвимость CVE-2021-41773 на вашем web сервере](#-------------------------cve-2021-41773----------web--------)
  * [Отправить фишинговое письмо](#---------------------------)
  * [** Установить SIEM систему (на ваше усмотрение Wazuh, ELK\EFK, cloud splunk)](#--------------siem-----------------------------wazuh--elk-efk--cloud-splunk-)

<small><i><a href='http://ecotrust-canada.github.io/markdown-toc/'>Table of contents generated with markdown-toc</a></i></small>

## Расследование инцидентов

> Изучить логи и примеры инцидентов, дать подробные ответы на данные вопросы:

[Link to SOC Questions](docs/1_Расследование%20инцидентов.docx)


## Создать скрипт на любом языке, который в информативном виде будет запускать скрипт с установкой:

* `AVML` - создание дампа оперативной памяти
* `Volatility` - фреймворк для работы с артефактами форензики
* `dwarf2json` - создание symbol table для кастомного ядра linux
* Сделает снимок Debug kernel для symbol table

Ответы:

> [Link to automatization sript](bin/2_avtomatization.sh)

```sh
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

```

## Автоматизировать процесс проверки url через virustotal

> Напишите небольшой скрипт для автоматизированной проверки url. Можно использовать любой язык программирования

Ответы:

> [Link to virustotal check script](bin/3_check-url.py)

```py

import requests
import base64
import json

# API ключ VirusTotal
print("Вставьте API key для доступа к VirusTotal")

# Ввод API ключа и URL для проверки
api_key = input("ВСТАВЬТЕ СВОЙ API КЛЮЧ: ")
url = input("Введите URL для проверки: ")

# Отправка запроса на VirusTotal
headers = {
    "Accept": "application/json",
    "x-apikey": api_key
}
# VirusTotal требует, чтобы URL был закодирован в base64
encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
response = requests.get(f"https://www.virustotal.com/api/v3/urls/{encoded_url}", headers=headers)

# Проверка статуса ответа
if response.status_code == 200:
    # Получение данных из ответа
    data = response.json()

    # Вывод результатов проверки
    print("Результаты проверки:")
    print("URL ID:", data["data"]["id"])
    last_analysis_stats = data["data"]["attributes"]["last_analysis_stats"]
    print("Безопасные:", last_analysis_stats.get("harmless", "N/A"))
    print("Подозрительные:", last_analysis_stats.get("suspicious", "N/A"))
    print("Злонамеренные:", last_analysis_stats.get("malicious", "N/A"))
    print("Недостоверные:", last_analysis_stats.get("undetected", "N/A"))

    # Результаты анализа по каждому движку
    print("Результаты анализа по движкам:")
    for engine, result in data["data"]["attributes"]["last_analysis_results"].items():
        print(f"{engine}: {result['category']}")
else:
    print("Ошибка:", response.status_code, response.text)


```

## Вы обнаружили уязвимость CVE-2021-41773 на вашем web сервере

> Вам необходимо создать задачу для IT по её устранению. Что нужно будет сделать специалисту, чтобы исправить эту уязвимость? Напишите plabook для специалиста SOC L1

[Link to CVE-2021-41773](https://nvd.nist.gov/vuln/detail/CVE-2021-41773)

[Link to Answer](docs/4_уязвимость%20CVE-2021-41773.docx)

## Отправить фишинговое письмо

* Установка setoolkit на ubuntu
* Отправьте мне письмо на адрес:`smilovesmirnov@gmail.com`
* от имени Teachmeskills с адресом отправителя `info@teachmeskills.com`
* В письме пришлите ссылку, на форму - копию страницы Zoom, где хранятся видео с занятий (https://us06web.zoom.us/signin#/login),
* код которой изменен таким образом, чтобы вы смогли получить введенный мной в форму флаг.
* В тексте письма укажите своё имя и фамилию - для уточнения кто выполнил задание
* p.s. Нужно зарегистрироваться в облаке, для получения белого ip
* Для отправки письма, можете использовать [emkei.cz](https://emkei.cz)

## ** Установить SIEM систему (на ваше усмотрение Wazuh, ELK\EFK, cloud splunk)

* Настроить логирование и отправку windows 10 логов
* Настроить логирование и отправку linux syslog / auditd 

Scrinshots:

![screenshot 1](images/130824-1.png)

![screenshot 1](images/Screenshot_1.png)

![screenshot 1](images/Screenshot_2.png)

![screenshot 1](images/Screenshot_3.png)