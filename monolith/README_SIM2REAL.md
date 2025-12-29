Simülasyon → Gerçek (Özet)

1) Blockchain (merkle root publish)
- `monolith.blockchain.merkle_root(leaves: List[bytes])` hesaplar.
- `monolith.blockchain.publish_merkle_root(leaves, private_key, rpc_url)` Sepolia/Goerli testnet'e merkle kökünü tx veri alanında yazar.
- Gereksinimler: `web3` ve `eth-account`. RPC URL'yi `WEB3_RPC_URL` ile verin.

2) Yerel LLM entegrasyonu
- `monolith.llm.analyze_vuln(prompt)` önce lokal Ollama sunucusuna istek atar (`OLLAMA_URL`), yoksa `OPENAI_API_KEY` ile OpenAI'ya düşer.
- Gereksinimler: `requests` ve isteğe bağlı `openai`.

3) Asenkron görev kuyruğu
- `monolith.celery_app` Celery'yi otomatik kullanır; yüklü değilse senkron stub sağlar.
- `monolith.tasks.run_nuclei` örnek bir görev sunar.
- Başlatma: Redis + Celery worker gerektirir; örnek:

  ```bash
  # Redis
  redis-server &

  # Celery worker (repository root)
  celery -A monolith.tasks.celery worker --loglevel=info
  ```

4) Entegrasyon önerisi
- `run_worker` gibi eski threading tabanlı fonksiyonları kuyruğa taşımak en mantıklısıdır: `run_nuclei.delay(target)` çağırın.
- Bu repo'da yapılan değişiklikler 'opt-in' tarzındadır: eğer paketler yüklü değilse kod güvenli olarak simülasyon modunda kalır.

5) CLI & HTTP route for Merkle publish
- CLI: `python cyber.py --publish-merkle <scan_id>` will collect `blockchain_evidence` rows for the given scan and publish their merkle root to the configured RPC using `WEB3_PRIVATE_KEY` and `WEB3_RPC_URL`.
- HTTP: POST or GET to `/blockchain/publish/<scan_id>` will perform the same action and return JSON `{status:'ok', tx_hash: '0x...'}` on success.

6) Requirements & quick start
- Recommended extra packages (install in your virtualenv):

  ```bash
  pip install web3 eth-account requests celery redis openai python-dotenv
  ```

+- Run Redis and a Celery worker to enable background scans:

  ```bash
  # start Redis
  redis-server &

  # start a Celery worker from project root
  celery -A monolith.tasks.celery worker --loglevel=info
  ```

8) Helper scripts
- `run_workers.sh`: starts `redis-server` (if present) and then starts a Celery worker.
- `publish_sample.sh`: demonstrates publishing merkle root from CLI (requires `WEB3_RPC_URL` & `WEB3_PRIVATE_KEY`).
  ```bash
  # start Redis
  redis-server &

  # start a Celery worker from project root
  celery -A monolith.tasks.celery worker --loglevel=info
  ```

7) Notes on safety
- Publishing to a testnet spends ETH (even if tiny). Use a funded testnet account and `WEB3_RPC_URL` pointing to a provider (Infura/Alchemy or local node). Keep the private key secure and never commit it.
