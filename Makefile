test:        ## Run policy unit tests
	@opa test policies

validate:    ## Lint/parse policies
	@opa check policies

clean:
	@rm -f dist/*

build: clean ## Build the OCI bundle
	@mkdir -p dist/
	@opa build -b policies -o dist/bundle.tar.gz
