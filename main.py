
import sys
import socket
import requests
import phonenumbers
from phonenumbers import timezone, geocoder, carrier
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import whois
from bs4 import BeautifulSoup


MAX_THREADS = 100
TIMEOUT = 2

class Цвета:
    ЗЕЛЕНЫЙ = '\033[92m'
    СИНИЙ = '\033[94m'
    КРАСНЫЙ = '\033[91m'
    ЖЕЛТЫЙ = '\033[93m'
    СБРОС = '\033[0m'

def показать_баннер():
    print(f"""{Цвета.СИНИЙ}
  _______               _             _____          _   
 |__   __|             | |           |  __ \        | |  
    | |_ __ ___  _ __ | | _____ _ __| |__) |___  __| |_ 
    | | '__/ _ \| '_ \| |/ / _ \ '__|  _  // _ \/ _` __|
    | | | | (_) | | | |   <  __/ |  | | \ \  __/ (_| |_ 
    |_|_|  \___/|_| |_|_|\_\___|_|  |_|  \_\___|\__\__|

  {Цвета.ЖЕЛТЫЙ}>> @cammelf! <<{Цвета.СБРОС}
""")

def анализ_номера(номер):
    try:
        parsed = phonenumbers.parse(номер)
        if not phonenumbers.is_valid_number(parsed):
            print(f"{Цвета.КРАСНЫЙ}[-] Невалидный номер!{Цвета.СБРОС}")
            return

        tz = timezone.time_zones_for_number(parsed)
        страна = geocoder.description_for_number(parsed, "ru")
        оператор = carrier.name_for_number(parsed, "ru")

        print(f"\n{Цвета.ЗЕЛЕНЫЙ}[+] Результаты по номеру {номер}:{Цвета.СБРОС}")
        print(f"{Цвета.СИНИЙ}├─ Страна: {страна}")
        print(f"├─ Оператор: {оператор}")
        print(f"└─ Часовой пояс: {', '.join(tz)}{Цвета.СБРОС}")

    except Exception as e:
        print(f"{Цвета.КРАСНЫЙ}[-] Ошибка: {e}{Цвета.СБРОС}")

def сканировать_порт(ip, порт):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        if sock.connect_ex((ip, порт)) == 0:
            print(f"{Цвета.ЗЕЛЕНЫЙ}[+] Порт {порт} открыт{Цвета.СБРОС}")
            return порт
    except:
        pass
    return None

def сканирование_портов(ip, start, end):
    print(f"\n{Цвета.СИНИЙ}[*] Сканируем {ip}...{Цвета.СБРОС}")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        результаты = list(executor.map(lambda p: сканировать_порт(ip, p), range(start, end+1)))
    открытые = [p for p in результаты if p]
    print(f"{Цвета.ЗЕЛЕНЫЙ}[+] Открытые порты: {открытые}{Цвета.СБРОС}")

def whois_инфо(домен):
    try:
        print(f"\n{Цвета.СИНИЙ}[*] WHOIS для {домен}:{Цвета.СБРОС}")
        whois_info = whois.whois(домен)
        print(f"{Цвета.ЗЕЛЕНЫЙ}├─ Регистратор: {whois_info.registrar}")
        print(f"├─ Дата создания: {whois_info.creation_date}")
        print(f"└─ DNS серверы: {whois_info.name_servers}{Цвета.СБРОС}")
    except Exception as e:
        print(f"{Цвета.КРАСНЫЙ}[-] Ошибка: {e}{Цвета.СБРОС}")

def dns_запрос(домен):
    try:
        print(f"\n{Цвета.СИНИЙ}[*] DNS записи для {домен}:{Цвета.СБРОС}")
        ответы = dns.resolver.resolve(домен, 'A')
        for rdata in ответы:
            print(f"{Цвета.ЗЕЛЕНЫЙ}├─ A запись: {rdata.address}{Цвета.СБРОС}")
    except Exception as e:
        print(f"{Цвета.КРАСНЫЙ}[-] Ошибка: {e}{Цвета.СБРОС}")

def проверить_http(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        r = requests.get(url, headers=headers, timeout=5)
        print(f"\n{Цвета.СИНИЙ}[*] Анализ {url}:{Цвета.СБРОС}")
        
        if 'server' in r.headers:
            print(f"{Цвета.ЖЕЛТЫЙ}[!] Сервер: {r.headers['server']}")
        
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            if not form.find('input', {'name': 'csrf_token'}):
                print(f"{Цвета.КРАСНЫЙ}[!] Форма без CSRF-защиты: {form.get('action', '?')}")

    except Exception as e:
        print(f"{Цвета.КРАСНЫЙ}[-] Ошибка: {e}{Цвета.СБРОС}")

def главное_меню():
    while True:
        показать_баннер()
        print(f"{Цвета.ЖЕЛТЫЙ}1. Анализ номера телефона")
        print("2. Сканирование портов")
        print("3. WHOIS информация")
        print("4. DNS запросы")
        print("5. Проверка HTTP уязвимостей")
        print(f"6. Выход{Цвета.СБРОС}")
        
        выбор = input(f"{Цвета.ЗЕЛЕНЫЙ}> Выберите опцию: {Цвета.СБРОС}")
        
        if выбор == "1":
            номер = input("Введите номер (с кодом страны): ")
            анализ_номера(номер)
        elif выбор == "2":
            ip = input("Введите IP: ")
            start = int(input("Начальный порт: "))
            end = int(input("Конечный порт: "))
            сканирование_портов(ip, start, end)
        elif выбор == "3":
            домен = input("Введите домен: ")
            whois_инфо(домен)
        elif выбор == "4":
            домен = input("Введите домен: ")
            dns_запрос(домен)
        elif выбор == "5":
            url = input("Введите URL (http://...): ")
            проверить_http(url)
        elif выбор == "6":
            sys.exit()
        else:
            print(f"{Цвета.КРАСНЫЙ}[-] Неверный выбор!{Цвета.СБРОС}")
        
        input("\nНажмите Enter чтобы продолжить...")

if __name__ == "__main__":
    главное_меню()