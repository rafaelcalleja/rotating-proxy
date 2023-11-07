DOCKER_TAG ?= 0.0.3
DOCKER_IMAGE ?= rafaelcalleja/rotatting-proxy:$(DOCKER_TAG)

.PHONY: run
run:
	DOCKER_IMAGE=$(DOCKER_IMAGE) docker compose up -d --force-recreate

.PHONY: build
build:
	docker build -t $(DOCKER_IMAGE) .

.PHONY: stop
stop:
	docker compose down

destroy:
	DOCKER_IMAGE=$(DOCKER_IMAGE) docker compose down --rmi local -v
	docker rmi $(DOCKER_IMAGE)

.PHONY: logs
logs:
	docker compose logs -f

push:
	docker push $(DOCKER_IMAGE)
