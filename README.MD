# Transformice Packet Sniffer

Bu proje, Transformice oyunu için bir paket dinleme aracıdır. Oyun içi paketleri yakalayıp analiz etmenizi sağlar.

## Özellikler

- Transformice TCP paketlerini dinleme
- Belirli bir port üzerinden paket yakalama
- Sohbet mesajlarını yakalama ve analiz etme
- Yakalanan paketleri JSON formatında kaydetme

## Kurulum

1. Gerekli Python paketlerini yükleyin:
```bash
pip install -r requirements.txt
```

2. Programı çalıştırın:
```bash
python Sniffer.py -p <port> [--only <chat|all>] [-o <çıktı_dosyası>]
```

## Kullanım

### Temel Kullanım
```bash
python Sniffer.py -p <port>
```

### Parametreler
- `-p, --port`: Dinlenecek Transformice TCP portu
- `--only`: Yalnızca belirtilen türdeki paketleri göster (chat veya all)
- `-o, --output`: Çıktı dosya adı (varsayılan: packets.json)

### Örnekler
```bash
# Belirli bir port üzerinden tüm paketleri dinle
python Sniffer.py -p 12345

# Belirli bir kullanıcının paketlerini dinle
python Sniffer.py -p 12345 --username "oyuncu123"

# Sadece sohbet mesajlarını dinle
python Sniffer.py -p 12345 --only chat
```

## Notlar

- Programı çalıştırmak için root/administrator yetkileri gerekebilir
- Yakalanan paketler otomatik olarak JSON formatında kaydedilir
- Programı durdurmak için Ctrl+C kullanın

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. 
