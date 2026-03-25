# Maintainer Notes — Proto / Dependency Regeneration

Bu dosya normal ilk kurulum için değildir. Zip artık şunlarla birlikte gelir:

- `sensor/go.sum`
- `sensor/proto/sensorv1/sensor.pb.go`
- `sensor/proto/sensorv1/sensor_grpc.pb.go`
- `manager/grpc/sensor_pb2.py`
- `manager/grpc/sensor_pb2_grpc.py`
- `ui/package-lock.json`

Normal kullanıcı akışında ekstra Claude Code adımı gerekmez. Bu belgeyi yalnızca şu durumlarda kullanın:

- `proto/sensor.proto` değiştiyse
- Go bağımlılıkları değiştiyse
- Generated dosyaları yeniden üretmek istiyorsanız

---

## Tercih Edilen Yol: Yerelde Yeniden Üretme

```bash
# Repo kökünde
make proto

# Go dependency metadata
cd sensor && go mod tidy && go test ./...

# UI lockfile yenilemek gerekirse
cd ../ui && npm install --package-lock-only
```

Notlar:

- `make proto` Go generator binary'lerini gerektiğinde kurar.
- `make proto` Python `grpcio-tools` için `.tools/proto-venv` altında yerel bir yardımcı venv oluşturur.
- `protoc` sistemde kurulu olmalıdır (`protobuf-compiler`).

---

## Claude Code ile Yeniden Üretme

Claude Code kullanacaksan, normal kurulum değil bakım/regeneration işi yaptığını belirt:

```text
Bu repo normal ilk kurulum için self-contained durumda.
Sadece maintainer regeneration yap:

1. Repo kökünde `make proto` çalıştır.
2. `cd sensor && go mod tidy && go test ./...` çalıştır.
3. `cd ui && npm install --package-lock-only` çalıştır.
4. Aşağıdaki dosyaların güncellendiğini doğrula:
   - sensor/go.sum
   - sensor/proto/sensorv1/sensor.pb.go
   - sensor/proto/sensorv1/sensor_grpc.pb.go
   - manager/grpc/sensor_pb2.py
   - manager/grpc/sensor_pb2_grpc.py
   - ui/package-lock.json
5. Herhangi bir hata varsa tam hata mesajını raporla.
```

---

## Doğrulama

```bash
ls sensor/proto/sensorv1/
ls manager/grpc/
wc -l sensor/go.sum
cd sensor && go test ./...
```
