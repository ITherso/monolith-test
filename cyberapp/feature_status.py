"""Read-only feature inventory. Importing this module never probes integrations."""

from dataclasses import dataclass

STATUS_LABELS = {
    "verified_management": "İzole testte doğrulandı",
    "simulation": "Simülasyon",
    "blocked_by_host_safety": "Güvenlik nedeniyle kapalı",
    "incomplete_offline": "Eksik / çevrimdışı",
    "external_config_required": "Dış yapılandırma gerekli",
    "unverified": "Çalışması doğrulanmadı",
}

DOCUMENTATION = (
    {
        "title": "CI kapsamı ve bilinen sınırlar",
        "url": "https://github.com/ITherso/monolith-test/blob/main/docs/CI_SCOPE.md",
    },
    {
        "title": "Yerel bilgisayar koruması",
        "url": "https://github.com/ITherso/monolith-test/blob/main/docs/HOST_SAFETY.md",
    },
)


@dataclass(frozen=True)
class FeatureStatus:
    id: str
    title: str
    status: str
    summary: str
    evidence: str
    verification_scope: str


FEATURES = (
    FeatureStatus(
        "admin_access_control",
        "Operasyonel ekran ve API yetkilendirmesi",
        "verified_management",
        "Eşleşen rotalar varsayılan olarak admin ister; incelenen okuma endpointleri oturum açmış kullanıcılara açıktır.",
        "cyberapp/authorization.py; tests/test_admin_access.py",
        "İzole Flask ve inert socket callback testleri. Özellik etkinleştirmez, host korumasını kaldırmaz veya çalışan sistemi izole etmez.",
    ),
    FeatureStatus(
        "management_auth",
        "Yönetim girişi ve oturumlar",
        "verified_management",
        "Yapılandırılmış hesaplar, kalıcı güvenli varsayılanlar ve oturum temizliği sınanıyor.",
        "tests/test_management_security.py",
        "İzole Flask sözleşmesi; çalışan bir kurulum veya tüm yetkilendirme yolları denetlenmedi.",
    ),
    FeatureStatus(
        "audit_view",
        "Audit kayıtlarının görüntülenmesi",
        "verified_management",
        "Kayıt alanları HTML olarak çalıştırılmadan metin olarak gösteriliyor; yönetici sınırı sınanıyor.",
        "tests/test_audit_security.py",
        "İzole Flask ve bellek içi SQLite; gerçek üretim verisi kullanılmadı.",
    ),
    FeatureStatus(
        "schema_upgrades",
        "Veritabanı şema geçişleri",
        "verified_management",
        "Temiz şema ve iki eski daldan birleşik şemaya geçiş, veri korunumu ile sınanıyor.",
        "tests/test_installation_regressions.py",
        "Geçici SQLite veritabanları; uygulama veya tarayıcı başlatılmadı.",
    ),
    FeatureStatus(
        "dashboard_display",
        "Panel verileri ve durum göstergeleri",
        "verified_management",
        "Bozuk veya aşırı büyük leaderboard/telemetri verileri paneli düşürmez. Araçlar çalıştırılmadan PATH üzerinden bulunur.",
        "cyberapp/dashboard_data.py; tests/test_dashboard_stability.py",
        "SDK ve dosya varlığı bağlantı veya çalışma kanıtı değildir; eksik telemetri ve ölçülmemiş oranlar açık gösterilir.",
    ),
    FeatureStatus(
        "scan_detail_display",
        "Tarama ayrıntılarının güvenli görüntülenmesi",
        "verified_management",
        "Kayıt alanları HTML olarak çalıştırılmadan görüntülenir; null ve sayısal intel/log alanları sayfayı düşürmez.",
        "cyberapp/routes/scans.py:details; tests/test_scan_view_safety.py",
        "Gerçek şablon ve bellek içi SQLite ile izole görüntüleme; tarama veya operasyonel modül çalıştırılmaz.",
    ),
    FeatureStatus(
        "offline_pdf_rendering",
        "Çevrimdışı metin ve tablo PDF üretimi",
        "verified_management",
        "Türkçe metin, başlık ve tablolar harici dönüştürücü olmadan PDF'ye aktarılır; script ve dış kaynaklar çalıştırılmaz.",
        "cyberapp/pdf_renderer.py; tests/test_pdf_renderer.py; tests/test_report_security.py",
        "Statik HTML alt kümesi. CSS, resimler ve etkileşimli grafikler PDF'ye çizilmez; tüm uygulama rapor yolları denetlenmedi.",
    ),
    FeatureStatus(
        "pdf_password_protection",
        "PDF parola koruması (AES-256)",
        "verified_management",
        "Gerçek geçici PDF örneklerinde AES-256, parola doğrulaması ve hata sırasında özgün dosyanın korunması sınandı.",
        "cyberapp/report_security.py; tests/test_report_security.py",
        "Çevrimdışı PDF üreticisi ve AES-256 geçici dosyalarda birlikte sınandı. Uygulama başlatılmadı; tüm rapor yolları denetlenmedi.",
    ),
    FeatureStatus(
        "release_metadata_check",
        "Yayın sürümü metadata kontrolü",
        "verified_management",
        "Kararlı yayımlanmış sürüm yanıtları, sayısal sürüm karşılaştırması ve 404/bağlantı/bozuk yanıt durumları sınandı.",
        "cyberapp/release_updates.py; tests/test_release_updates.py",
        "HTTP yanıtları testlerde taklit edildi; canlı GitHub kontrolü, yazılım indirme veya kurma yapılmadı.",
    ),
    FeatureStatus(
        "template_report_summary",
        "Şablon tabanlı rapor özeti",
        "simulation",
        "Özet, sağlanan günlük istatistikleri ve sabit şablonlarla üretilir; AI modeli çağrılmaz.",
        "tools/report_generator.py:AISummaryGenerator",
        "Kaynak incelemesi. Eski AI sınıfı ve ayar adları korunur; canlı AI veya tüm rapor zinciri doğrulanmadı.",
    ),
    FeatureStatus(
        "passive_jsonl_review",
        "Sağlanan JSONL olaylarının pasif incelenmesi",
        "verified_management",
        "Yerel JSONL dosyası ve sonradan eklenen kayıtlar okunur; seçili olaylar insan incelemesi için işaretlenir.",
        "cyberapp/passive_monitor.py; tests/test_passive_monitor.py",
        "Çevrimdışı günlük sözleşmesi. OS olayı veya ağ paketi toplamaz; uyarı ihlal kanıtı değildir.",
    ),
    FeatureStatus(
        "live_monitoring",
        "Canlı OS / paket izleme",
        "external_config_required",
        "Pasif inceleyici sağlanan bir JSONL olay kaynağı ister; canlı veri toplama bağlantısı içermez.",
        "cyberapp/passive_monitor.py",
        "EDR veya canlı OS olay toplayıcısının yerine geçmez; gerçek olay kaynağı entegrasyonu doğrulanmadı.",
    ),
    FeatureStatus(
        "host_startup",
        "Windows / WSL operasyonel başlangıç",
        "blocked_by_host_safety",
        "Korunan giriş noktaları özellik modüllerini yüklemeden durur. Açma anahtarı bulunmaz.",
        "cyberapp/host_safety.py; tests/test_host_safety.py",
        "Kasıtlı koruma. Bu durdurma bir sandbox veya bilgisayar temizliği kanıtı değildir.",
    ),
    FeatureStatus(
        "local_atomic_execution",
        "Yerel atomic komut çalıştırma",
        "blocked_by_host_safety",
        "Gerçek yerel komut yürütücüsü koşulsuz kapalıdır; yalnızca çevrimdışı simülasyon kalır.",
        "tools/purple_team_validator.py; tests/test_host_safety.py",
        "Kasıtlı koruma; hedef adı bilgisayardan ayrı bir yürütme sınırı oluşturmaz.",
    ),
    FeatureStatus(
        "training_routes",
        "Güvensiz eğitim endpointleri",
        "blocked_by_host_safety",
        "Kasıtlı açık içeren eğitim rotaları yönetim uygulamasına kaydedilmez.",
        "tests/test_vulnerable.py",
        "Yönetim yüzeyinde bulunmamaları izole testle doğrulanır; yeniden açma işlemi sunulmaz.",
    ),
    FeatureStatus(
        "cli_web_sample",
        "CLI web uygulaması örnek raporu",
        "simulation",
        "URL bir etiket olarak kullanılır; örnek rapor üretilir, istek gönderilmez veya açık doğrulanmaz.",
        "cyberapp/cli.py; tests/test_simulation_contract.py",
        "Bu seçenek gerçek web taraması sonucu veya güvenlik testi kapsamı bildirmez.",
    ),
    FeatureStatus(
        "quantum_demo",
        "Kuantum kriptografi demosu",
        "simulation",
        "Eğitim amaçlıdır. Desteklenmeyen imza doğrulaması başarısız kapanır ve API 501 döndürür.",
        "cybermodules/quantum_crypto.py; cyberapp/routes/quantum.py",
        "Denetlenmiş veya gerçek veriyi korumaya uygun post-kuantum kriptografi değildir.",
    ),
    FeatureStatus(
        "oauth_demo",
        "OAuth token / MFA toplama demosu",
        "simulation",
        "Örnek token ve başarı etiketleri üretir; paket oluşturulması gerçek aktarım veya MFA sonucu değildir.",
        "tools/cred_harvest.py",
        "Kaynak incelemesi. Gerçek kimlik sağlayıcısıyla oturum veya token değişimi doğrulanmadı.",
    ),
    FeatureStatus(
        "calculator_helper",
        "Calculator DLL yardımcısı",
        "incomplete_offline",
        "Kaynak, örnek script metni, sabit adresler ve sahte DLL verileri içerir; çalışan enjeksiyon kanıtı sunmaz.",
        "cybermodules/memory_dll_loader.py",
        "Kaynak incelemesi; yerel process veya üretilen script çalıştırılmadı.",
    ),
    FeatureStatus(
        "can_demo",
        "CAN araç tanıma ve trafik örnekleri",
        "simulation",
        "İncelenen tanıma ve dinleme yolları araç bilgisi ve CAN karelerini rastgele üretir.",
        "tools/automotive_canbus.py",
        "Gerçek araç veya CAN donanımı üzerinde doğrulanmadı.",
    ),
    FeatureStatus(
        "gps_signal",
        "GPS sinyal dosyası",
        "incomplete_offline",
        "İncelenen üretici gerçek IQ örnekleri yerine yer tutucu dosya oluşturur.",
        "tools/orbital_rf_warfare.py",
        "Kaynak incelemesi; RF cihazı veya yayın işlemi kullanılmadı.",
    ),
    FeatureStatus(
        "rf_demo",
        "GSM taraması ve uydu görüntüsü bilgileri",
        "simulation",
        "İncelenen yollar örnek hücre verisi ve simüle hava görüntüsü bilgileri üretir.",
        "tools/orbital_rf_warfare.py",
        "Gerçek şebeke taraması veya uydu görüntüsü çözümü kanıtı değildir.",
    ),
    FeatureStatus(
        "cloud_assets",
        "Bulut varlık gösterimi",
        "simulation",
        "Gösterim sonuçları gerçek sağlayıcı hesabından doğrulanmış varlık envanteri sayılmaz.",
        "cyberapp/routes/cloud_assets.py; tools/cloud_assets_discovery.py",
        "Gerçek bulut kimliği, SDK oturumu ve sağlayıcı sonucu bu kapsamda doğrulanmadı.",
    ),
    FeatureStatus(
        "llm_provider",
        "Dış LLM sağlayıcısı",
        "external_config_required",
        "Yerel model hizmeti veya yapılandırılmış sağlayıcı gerekir; yokluğunda simülasyon yanıtına düşebilir.",
        "monolith/llm.py",
        "Canlı sağlayıcı bağlantısı, kimlik bilgisi veya model yanıtı sınanmadı.",
    ),
    FeatureStatus(
        "vr_export",
        "Unity / VR dışa aktarımı",
        "external_config_required",
        "Dış Unity komutu yoksa veya başarısızsa yer tutucu sahne çıktısı üretilebilir.",
        "tools/vr_viz.py",
        "JSON veya sahne dosyası oluşması gerçek Unity/VR çalışmasını doğrulamaz.",
    ),
    FeatureStatus(
        "ai_predictor",
        "Eski AI açık tahmin modülü",
        "incomplete_offline",
        "Tahmin sınıfı, enum tanımında bulunmayan kategorilere başvurur; modül yüklenmesini engelleyen kusur vardır.",
        "cybermodules/ai_vuln.py:29,457,868",
        "Kaynak incelemesi; diğer AI ekranlarının bütünü için bir başarısızlık hükmü değildir.",
    ),
    FeatureStatus(
        "legacy_source_defects",
        "Eski kaynakların yüklenebilirliği",
        "incomplete_offline",
        "Eski operasyonel kaynaklarda Python 3.11 sözdizimi, Unicode kaçışı ve sayısal sabit kusurları belgelenmiştir.",
        "docs/CI_SCOPE.md; cybermodules/event_driven_c2.py; cybermodules/kernel_callbacks_bypass.py",
        "Yönetim testleri bu modülleri onarmaz veya çalıştırmaz; yeşil CI bütün depoyu doğrulamaz.",
    ),
    FeatureStatus(
        "operational_runtime",
        "Diğer operasyonel modüller ve entegrasyonlar",
        "unverified",
        "C2, platforma özgü işlemler, AD ve diğer entegrasyonlar yönetim güvenliği test kapsamının dışındadır.",
        "docs/CI_SCOPE.md",
        "Çalışıyor veya bozuk hükmü verilmez. Eski kaynaklarda belgelenmiş sözdizimi ve yükleme kusurları vardır.",
    ),
)


def feature_status_snapshot() -> dict[str, object]:
    """Return fresh serializable data, without imports, network I/O, or probes."""
    counts = dict.fromkeys(STATUS_LABELS, 0)
    features = []
    for feature in FEATURES:
        if feature.status not in STATUS_LABELS:
            raise ValueError(f"Unknown feature status: {feature.status}")
        counts[feature.status] += 1
        features.append(
            {
                "id": feature.id,
                "title": feature.title,
                "status": feature.status,
                "status_label": STATUS_LABELS[feature.status],
                "summary": feature.summary,
                "evidence": feature.evidence,
                "verification_scope": feature.verification_scope,
            }
        )
    return {
        "schema_version": 1,
        "read_only": True,
        "live_probe_performed": False,
        "inventory_complete": False,
        "production_certified": False,
        "notice": (
            "Kaynak incelemesi ve izole yönetim testlerine dayalı temsilî envanterdir. "
            "Canlı kurulum denetimi veya bütün özelliklerin çalıştığına dair onay değildir."
        ),
        "statuses": dict(STATUS_LABELS),
        "counts": counts,
        "features": features,
        "documentation": [dict(document) for document in DOCUMENTATION],
    }
