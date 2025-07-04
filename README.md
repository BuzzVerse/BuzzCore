
## Start InfluxDB v2 with automated setup
```bash
docker run -d -p 8086:8086 \                                                                                                                                     
  -v "$PWD/data:/var/lib/influxdb2" \
  -v "$PWD/config:/etc/influxdb2" \
  -e DOCKER_INFLUXDB_INIT_MODE=setup \
  -e DOCKER_INFLUXDB_INIT_USERNAME=admin \
  -e DOCKER_INFLUXDB_INIT_PASSWORD=zaq1@WSX \
  -e DOCKER_INFLUXDB_INIT_ORG=BuzzVerse \
  -e DOCKER_INFLUXDB_INIT_BUCKET=BuzzNode \
  influxdb:2
```

## Generate access token
```bash
docker exec -it $(docker ps -q -f ancestor=influxdb:2) influx auth create --read-buckets --write-buckets
```
Copy the token and save it in a application.properties file

--- 

## ✅ Build and deploy BuzzCore

```bash
# Build multi-platform Docker image and push to registry
docker buildx build --platform linux/arm64/v8,linux/amd64 -t bykowskiolaf/buzzcore:latest . --push

# Upgrade (or install) the Helm release
helm upgrade -i buzzcore ./helm-chart -f ./helm-chart/values.yaml -n buzzcore
```
