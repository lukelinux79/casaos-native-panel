.PHONY: deps build run test vet install

APP_NAME=casaos-native-panel
PREFIX=/opt/$(APP_NAME)

all: build

deps:
	go mod download

build:
	go build -o bin/$(APP_NAME) ./cmd/server

run:
	go run ./cmd/server

test:
	go test ./...

vet:
	go vet ./...

# install copies binary, UI and systemd unit; run as root after `make build`.
install:
	install -d $(PREFIX) $(PREFIX)/web
	install -m 0755 bin/$(APP_NAME) $(PREFIX)/$(APP_NAME)
	install -m 0644 web/* $(PREFIX)/web/
	install -m 0644 deploy/$(APP_NAME).service /etc/systemd/system/$(APP_NAME).service
	systemctl daemon-reload
	@echo "Next: create /etc/casaos-native-panel.env with CASAOS_ADMIN_USER and CASAOS_ADMIN_PASSWORD,"
	@echo "then: systemctl enable --now $(APP_NAME)"
