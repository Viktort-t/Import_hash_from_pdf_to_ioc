import re
import os
import uuid
import requests
from datetime import datetime, timezone
import xml.etree.ElementTree as elementTree
import fitz  # PyMuPDF
from dotenv import load_dotenv
import os

load_dotenv()


def identify_hashes(text):
    """
    Определяет хэши и их типы в тексте.

    :param text: Текст, в котором нужно искать хэши.
    :type text: str
    :return: Словарь, где ключи - типы хэшей ('md5', 'sha1', 'sha256', 'sha512'), а значения - списки найденных хэшей данного типа.
    :rtype: dict
    """
    hash_patterns = {
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
        'sha512': r'\b[a-fA-F0-9]{128}\b'
    }
    found_hashes = {key: [] for key in hash_patterns.keys()}
    for hash_type, pattern in hash_patterns.items():
        matches = re.findall(pattern, text)
        found_hashes[hash_type].extend(matches)
    return found_hashes


def extract_hashes_from_pdf(pdf_path):
    """
    Извлекает текст из PDF-файла и определяет хэши в тексте.

    :param pdf_path: Путь к PDF-файлу.
    :type pdf_path: str
    :return: Словарь найденных хэшей, классифицированных по типам.
    :rtype: dict
    """
    text = ""
    try:
        with fitz.open(pdf_path) as doc:
            for page_num in range(len(doc)):
                page = doc.load_page(page_num)
                text += page.get_text()
    except Exception as e:
        print(f"Ошибка при извлечении текста из PDF: {e}")
    return identify_hashes(text)


def generate_ioc_id():
    """
    Генерирует уникальный идентификатор для IOC (Indicator of Compromise).

    :return: Уникальный UUID в виде строки.
    :rtype: str
    """
    return str(uuid.uuid4())


def is_hash_malicious(hash_value):
    """
    Проверяет хэш на сайте Kaspersky OpenTip через API.

    :param hash_value: Хэш для проверки.
    :type hash_value: str
    :return: True, если хэш безопасен (ответ 200), иначе False.
    :rtype: bool
    """
    url = "https://opentip.kaspersky.com/ui/lookup"

    # Заголовки запроса
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "ru,en;q=0.9",
        "content-type": "application/octet-stream",
        "cym9cgwjk": os.getenv("cym9cgwjk"),
        "sec-ch-ua": "\"Chromium\";v=\"130\", \"YaBrowser\";v=\"24.12\", \"Not?A_Brand\";v=\"99\", \"Yowser\";v=\"2.5\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "x-kl-saas-ajax-request": "Ajax_Request",
    }

    # Тело запроса
    payload = {
        "query": hash_value,
        "silent": False
    }
    try:
        response = requests.post(url, json=payload, headers=headers)
        return response.status_code == 200
    except requests.RequestException as e:
        print(f"Ошибка при проверке хэша {hash_value}: {e}")
        return False


def create_single_ioc_file(hashes, threat_name, output_dir):
    """
    Создает один IOC-файл для заданного набора хэшей.

    :param hashes: Словарь хэшей, классифицированных по типам.
    :type hashes: dict
    :param threat_name: Название угрозы, связанной с IOC.
    :type threat_name: str
    :param output_dir: Директория для сохранения созданного IOC-файла.
    :type output_dir: str
    :return: Путь к созданному IOC-файлу.
    :rtype: str
    """
    ioc = elementTree.Element('ioc', {
        'id': generate_ioc_id(),
        'last-modified': datetime.now(timezone.utc).isoformat(),
        'xmlns': 'http://schemas.mandiant.com/2010/ioc',
        'version': '1.1'
    })
    definition = elementTree.SubElement(ioc, 'definition')
    indicator = elementTree.SubElement(definition, 'Indicator', {'operator': 'OR'})

    # Файл для сохранения отфильтрованных хэшей
    text_file_path = os.path.join(output_dir, f"{threat_name}_hashes.txt")
    with open(text_file_path, 'a', encoding='utf-8') as text_file:
        for hash_type, hash_list in hashes.items():
            for hash_value in hash_list:
                if not is_hash_malicious(hash_value):
                    # Добавляем в IOC-файл
                    indicator_item = elementTree.SubElement(indicator, 'IndicatorItem', {'condition': 'is'})
                    elementTree.SubElement(indicator_item, 'Context', {
                        'document': 'FileItem',
                        'search': f'FileItem/{hash_type.upper()}'
                    })
                    content = elementTree.SubElement(indicator_item, 'Content', {'type': hash_type})
                    content.text = hash_value

                    # Сохраняем в текстовый файл
                    text_file.write(f"{hash_type}: {hash_value}\n")

    # Сохранение IOC-файла
    output_path = os.path.join(output_dir, f"{threat_name}_{generate_ioc_id()}.ioc")
    tree = elementTree.ElementTree(ioc)
    try:
        tree.write(output_path, encoding='utf-8', xml_declaration=True)
        print(f"Создан IOC-файл: {output_path}")
    except Exception as e:
        print(f"Ошибка при сохранении IOC-файла: {e}")
    return output_path


def split_and_save_ioc(hashes_collection, output_dir, max_file_size=2 * 1024 * 1024):
    """
    Разделяет коллекции хэшей на несколько IOC-файлов, если они превышают заданный размер.

    :param hashes_collection: Словарь, где ключи - названия угроз, а значения - словари хэшей.
    :type hashes_collection: dict
    :param output_dir: Директория для сохранения созданных IOC-файлов.
    :type output_dir: str
    :param max_file_size: Максимальный размер файла в байтах. По умолчанию 2 МБ.
    :type max_file_size: int
    :return: Список путей к созданным IOC-файлам.
    :rtype: list
    """
    os.makedirs(output_dir, exist_ok=True)
    created_files = []
    for threat_name, hashes in hashes_collection.items():
        file_path = create_single_ioc_file(hashes, threat_name, output_dir)
        if os.path.getsize(file_path) > max_file_size:
            print(f"Файл {file_path} превышает {max_file_size} байт. Рекомендуется разделить данные.")
        created_files.append(file_path)
    return created_files


def process_pdf_to_ioc(pdf_path, threat_name, output_dir):
    """
    Обрабатывает PDF-документ, извлекает хэши и создает IOC-файлы.

    :param pdf_path: Путь к PDF-файлу.
    :type pdf_path: str
    :param threat_name: Название угрозы, связанной с хэшами.
    :type threat_name: str
    :param output_dir: Директория для сохранения созданных IOC-файлов.
    :type output_dir: str
    :return: Список путей к созданным IOC-файлам.
    :rtype: list
    """
    hashes = extract_hashes_from_pdf(pdf_path)
    created_files = split_and_save_ioc({threat_name: hashes}, output_dir)
    return created_files


def main():
    """
    Основная функция для обработки PDF-документа и создания IOC-файлов.

    Путь к PDF-файлу, название угрозы и директория вывода указаны в коде для демонстрации.
    """
    pdf_path = r"C:\Users\chern\Downloads\Documents\test.pdf"  # Укажите путь к вашему PDF-документу
    threat_name = pdf_path.split('\\')[-1].replace(".pdf", '')
    output_directory = "output_ioc"

    created_files = process_pdf_to_ioc(pdf_path, threat_name, output_directory)
    print(f"Создано {len(created_files)} IOC-файлов.")


if __name__ == '__main__':
    main()
