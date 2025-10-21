import os #İşletim sistmi ile etkileşim için ve dosya işlemleri için
import sys #sistemle alakalı işlemler özellikle exit için
import time #Zamanla alakalı işlemler için
import requests #HTTP istekleri GET, POST vb.
import json #API'den gelen JSON verilerini pythonda işlemek için

from xml.etree.ElementTree import Element, SubElement, tostring #XML verisi oluşturmak daha sonra kaydedebilmek için 
from xml.dom import minidom #XML verisini okunabilir hale getirmek için kullanılacak
from dotenv import load_dotenv #.env dosyasından api keyi çekebilmek için

load_dotenv() # .env dosyasını yükle

API_KEY = os.getenv("VT_API_KEY") # .env dosyasından api keyi çek

VT_API_URL_FILES = "https://www.virustotal.com/api/v3/files" #Dosya tarama için api urlsi
VT_API_URL_ANALYSES = "https://www.virustotal.com/api/v3/analyses/{}" #Dosya analiz sonuçlarını çekmek için api urlsi

REQUESTS_DELAY_SECONDS = 16 #API istekleri için beklenecek süre ücretsiz sürede 15sn istek limiti

MAX_FILE_SIZE_MB =32 #Maksimum dosya boyutu 32MB ücretsiz sürümde


def check_file_size(file_path):
    size_in_bytes = os.path.getsize(file_path) #Dosya boyutunu byte cinsinden al

    size_in_mb = size_in_bytes / (1024 * 1024) #Byte'ı MB'a çevir

    if size_in_mb > MAX_FILE_SIZE_MB:
        print(f"[-] Hata: {os.path.basename(file_path)} dosyasi {size_in_mb:.2f}MB boyutunda. {MAX_FILE_SIZE_MB}MB limitini asiyor.")
        return False
    return True

def upload_apk(file_path, api_key):
    headers = {"x-apikey": api_key} #API anahtarını başlıklara ekle

    with open(file_path, "rb") as file: #dosyayı binary modda aç
        files = {"file": (os.path.basename(file_path), file)}
        try:
            response = requests.post(VT_API_URL_FILES, headers=headers, files=files) #Dosyayı virustotal api'sine yükle

            if response.status_code == 200:
                analysis_id = response.json()["data"]["id"]
                print(f"[+] {os.path.basename(file_path)} dosyasi yuklendi. Analysis ID: {analysis_id}")
                return analysis_id
            else:
                print(f"[-] Hata: {os.path.basename(file_path)} dosyasi yuklenemedi. Status Code: {response.status_code}")
                return None
        except requests.RequestException as e:
            print(f"[-] Hata: {os.path.basename(file_path)} dosyasi yuklenirken bir hata olustu. Hata: {e}")
            return None
        
def get_analysis_report(analysis_id, api_key):
    print("analiz sonucu getiriliyor...")
    headers = {"x-apikey": api_key} #API anahtarını başlıklara ekle
    url = VT_API_URL_ANALYSES.format(analysis_id) #Analiz sonuçları için url'yi oluştur
    try:
        response = requests.get(url, headers=headers) #Analiz sonuçlarını çek
        if response.status_code == 200:
            result = response.json() #JSON verisini al
            
            if result["data"]["attributes"]["status"] == "completed":
                print("[+] Analiz tamamlandi.")
                return result
            else:
                print("[-] Analiz tamamlanmadi. Lutfen daha sonra tekrar deneyin.")
                return None
    except requests.RequestException as e:
        print(f"[-] Hata: Analiz sonucu getirilirken bir hata olustu. Hata: {e}")
    return None

def save_reports(report_data, base_filename):
    #gelen veriyi (JSON gelecek) formala kaydet ve yaz 

    with open(f"{base_filename}.json", "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4, ensure_ascii=False)
    print(f"[+] Rapor kaydedildi: {base_filename}.json")

    stats = report_data["data"]["attributes"]["stats"]
    results = report_data["data"]["attributes"]["results"]

    with open(f"{base_filename}.txt","w", encoding = "utf-8") as f:
        f.write(f"VirusTotal Analiz Raporu - {base_filename}\n")
        for key, value in stats.items():
            f.write(f"{key.capitalize()}: {value}\n")
        f.write("\nZarar veya Supheli Sonuclar:\n")
        positives = {k:v for k,v in results.items() if v['category'] in ['malicious','suspicious']}
        if positives:
            for engine, result in positives.items():
                f.write(f"Motor: {engine}\n")
                f.write(f"Kategori: {result['category']}\n")
                f.write(f"Sonuc: {result['result']}\n\n")
        else:
            f.write("Tum motorlar temiz sonuc verdi.\n")
    print(f"[+] Rapor kaydedildi: {base_filename}.txt")

    root = Element('VirusTotalReport')
    stats_elem = SubElement(root, 'Stats')
    for key,value in stats.items():
        SubElement(stats_elem,key).text = str(value)
    
    detections_elem = SubElement(root, 'Detections')
    positives = {k:v for k,v in results.items() if v['category'] in ['malicious','suspicious']}
    for engine, result in positives.items():
        engine_elem = SubElement(detections_elem, 'Engine', name=engine)
        SubElement(engine_elem, 'Category').text = result['category']
        SubElement(engine_elem, 'Result').text = result['result']
    
    xml_str = minidom.parseString(tostring(root)).toprettyxml(indent="   ") #XML verisini okunabilir hale getir
    with open(f"{base_filename}.xml", "w", encoding="utf-8") as f:
        f.write(xml_str)
    print(f"[+] Rapor kaydedildi: {base_filename}.xml")

def main():

    if not API_KEY:
        print("[-] Hata: VIRUSTOTAL_API_KEY .env dosyasinda bulunamadi.")
        sys.exit(1) #API key yoksa programı sonlandır
    
    apk_directory = "apks" #APK dosyalarının bulunduğu dizin
    if not os.path.isdir(apk_directory):
        print(f"[-] Hata: '{apk_directory}' dizini bulunamadi.")
        sys.exit(1) #Dizin yoksa programı sonlandır
    
    output_reports_dir = "reports"
    os.makedirs(output_reports_dir, exist_ok=True) #Raporların kaydedileceği dizini oluştur
    
    summary_lines = [] #Özet rapor için satırlar

    apk_files = [f for f in os.listdir(apk_directory) if f.lower().endswith(".apk")] #Dizindeki tüm apk dosyalarını listele

    if not apk_files:
        print("[-] Hata: 'apks' dizininde taranacak APK dosyasi bulunamadi.")
        sys.exit(0) #Dizin boşsa programı sonlandır
    
    for filename in apk_files:
        file_path = os.path.join(apk_directory, filename)

        if not check_file_size(file_path):
            continue

        analysis_id = upload_apk(file_path, API_KEY)

        if analysis_id:
            report = None
            
            while report is None:
                time.sleep(REQUESTS_DELAY_SECONDS)
                report = get_analysis_report(analysis_id, API_KEY)
            
            print(f"[+] {filename} dosyasi icin analiz raporu alindi.")

            base_filename_without_ext = os.path.splitext(filename)[0]
            report_path_base = os.path.join(output_reports_dir, base_filename_without_ext)
            save_reports(report, report_path_base)

            stats = report["data"]["attributes"]["stats"]
            positives = stats.get("malicious",0) + stats.get("suspicious",0)
            total_engines = sum(stats.values())
            summary_lines.append(
                f"Dosya Adi: {filename}\n"
                f"Tespit Orani: {positives} / {total_engines}\n"
                f"  Zararsiz (Harmless): {stats.get('harmless', 0)}\n"
                f"  Tespit Edilemedi (Undetected): {stats.get('undetected', 0)}\n"
                f"  Supheli (Suspicious): {stats.get('suspicious', 0)}\n"
                f"  Zararli (Malicious): {stats.get('malicious', 0)}\n"
                f"--------------------------------------------------\n"
            )
        print("API limitimiz dahilinde istek yapabilmek icin bekleniyor...")
        time.sleep(REQUESTS_DELAY_SECONDS)

    if summary_lines:
        with open("results.txt", "w", encoding="utf-8") as f:
            f.write("VirusTotal APK Tarama Sonuclari\n")
            f.writelines(summary_lines)
        print("[+] Taramalar tamamlandi. Sonuclar results.txt dosyasina kaydedildi.")
    else:
        print("[-] Hata: Taranacak uygun APK dosyasi bulunamadi.")
    
if __name__ == "__main__":
    main()


    
