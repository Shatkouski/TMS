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

