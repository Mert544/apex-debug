# CI/CD Entegrasyonu

Apex Debug bağımsız bir projedir ve herhangi bir CI/CD pipeline'ına entegre edilebilir.

## GitHub Actions

`.github/workflows/apex-debug.yml` dosyasını projene kopyala.

### Kullanım Modları

**1. Katı Mod (Strict)** — Her CRITICAL bulgu pipeline'ı durdurur:
```bash
apex analyze . --min-severity critical
```

**2. Diff Modu** — Sadece PR'daki değişen satırları kontrol eder:
```bash
apex analyze . --diff-staged --min-severity medium
```

**3. Baseline Modu** — Bilinen sorunları görmezden gelir, sadece yenilerini raporlar:
```bash
# Bir kere çalıştır, baseline oluştur
apex analyze . --save-baseline apex-baseline.json

# CI'da sadece yeni sorunları kontrol et
apex analyze . --baseline apex-baseline.json --min-severity medium
```

**4. Auto-fix Modu** — Basit sorunları otomatik düzeltir:
```bash
apex analyze . --diff-staged --fix
```

## Pre-commit Hook

`examples/pre-commit-hook.sh` dosyasını `.git/hooks/pre-commit` olarak kopyala ve çalıştırılabilir yap:

```bash
cp examples/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Bu, commit öncesinde sadece staged değişiklikleri analiz eder ve bulgu varsa commit'i engeller.

## GitLab CI

```yaml
apex-debug:
  image: python:3.11
  script:
    - pip install git+https://github.com/your-org/apex-debug.git
    - apex analyze . --baseline apex-baseline.json --output sarif
  artifacts:
    reports:
      sast: report.sarif
```

## Özellikler

- **Bağımsız**: Apex Orchestrator olmadan çalışır
- **Hızlı**: Diff modu büyük projelerde saniyeler içinde biter
- **Güvenli**: Auto-fix sadece %100 güvenli dönüşümler yapar
- **Entegre**: SARIF çıktısı GitHub Security tab'ına yüklenir
