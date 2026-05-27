rm -rf certs/*

rm -rf ../cactus-data/
rm -rf ../cactus-mirror-data/

go run update_config_keys.go config.json
