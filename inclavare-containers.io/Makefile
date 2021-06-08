image := jimmysong/website-builder:2019-07-18
docker := docker run -t -i --sig-proxy=true --rm -v $(shell pwd):/site -w /site -p 1313:1313 $(image)
build:
	@$(docker) scripts/build-site.sh
lint:
	@$(docker) scripts/lint-site.sh
install:
	@$(docker) scripts/install-dependency.sh
serve:
	@$(docker) hugo serve --bind 0.0.0.0 --disableFastRender
