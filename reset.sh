rm -rf certs/*

rm -rf ../cactus-data/
rm -rf ../cactus-mirror-data/

gotip run -tags mldsa update_config_keys.go config.json
