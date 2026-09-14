# APT CTI Arama Motoru (APT CTI Search Engine)

Bu proje, Siber Tehdit İstihbaratı CTI araştırmacıları ve analistleri için geliştirilmiş hızlı ve asenkron çalışan web tabanlı bir arama motorudur. Bir APT grubu adını, diğer ismini veya MITRE ID'sini kullanarak **MITRE ATT&CK** ve **Malpedia** veritabanlarından eşzamanlı olarak bilgi toplar ve kullanıcı dostu bir arayüzde sunar.

## Özellikler

- **Eşzamanlı Tarama:** Asenkron mimari sayesinde MITRE ATT&CK ve Malpedia kaynakları aynı anda taranır, veriler milisaniyeler içinde ekrana yansır.
- **Akıllı Alias & ID Araması:** Grubun ana adını bilmeseniz bile diğer isimlerinden (örn. *admin@338*) veya MITRE ID'sinden (örn. *G0018*) arama yaparak doğru gruba ulaşabilirsiniz.
- **Kademeli Malpedia Algoritması:** Malpedia'nın doğrudan arama desteklemeyen API'sine karşı, MITRE'den elde edilen alternatif isimleri kullanarak hedef grubu tespit eden özel bir algoritma içerir.
- **Teknik Listeleme:** MITRE ATT&CK veritabanındaki saldırı modelleri parse edilerek, ilgili APT grubunun kullandığı tüm teknikler (T1059 vb.) listelenir.
- **Bağımsız Modern Arayüz:** Backend ve Frontend birbirinden tamamen bağımsız çalışır. Arayüz saf HTML, CSS ve JavaScript ile yazılmış olup ekstra bir kütüphane gerektirmez.

## Kullanılan Teknolojiler

- **Backend:** Python, FastAPI, Uvicorn, HTTPX, Pydantic, asyncio
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **Veri Kaynakları:**
  - MITRE ATT&CK Enterprise (JSON)
  - Malpedia REST API

## Kurulum ve Çalıştırma

Projenin çalışması için sisteminizde Python 3.7+ kurulu olması gerekmektedir.

### 1. Gereksinimlerin Yüklenmesi
Terminal veya komut satırını açarak gerekli Python kütüphanelerini yükleyin:

```bash
pip install fastapi uvicorn httpx pydantic
```
Ardından kurulu olduğu dizine gidip aşağıdaki komutu girerek frontendi çalıştırabilirsiniz.

```bash
uvicorn main:app --reload
```
