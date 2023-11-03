DOCKER_IMAGE ?= rafaelcalleja/rotatting-proxy
DOCKER_TAG ?= 0.0.2

.PHONY: run
run:
	DOCKER_IMAGE=$(DOCKER_IMAGE) DOCKER_TAG=$(DOCKER_TAG) docker compose up -d --force-recreate

.PHONY: build
build:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

.PHONY: stop
stop:
	docker compose down

destroy:
	DOCKER_IMAGE=$(DOCKER_IMAGE) DOCKER_TAG=$(DOCKER_TAG) docker compose down --rmi local -v
	docker rmi $(DOCKER_IMAGE):$(DOCKER_TAG)

.PHONY: logs
logs:
	docker compose logs -f

push:
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)

