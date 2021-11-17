SCHEMA_DIR = $(PWD)/identity-schemas
GODIR      = $(PWD)/generated/go
TSDIR      = $(PWD)/generated/ts
TOOLS      = \
	github.com/atombender/go-jsonschema/cmd/gojsonschema@master \
	github.com/mikefarah/yq/v4@latest

default: generate

generate:
	@for folder in $(shell ls ${SCHEMA_DIR}); do \
		for yamlschema_filename in $$(find ${SCHEMA_DIR}/$${folder} -name '*.yaml'); do \
			mkdir -p $(SCHEMA_DIR)/$${folder}/json; \
			mkdir -p $(GODIR)/$${folder}; \
			mkdir -p $(TSDIR)/$${folder}; \
			basefilename=$$(basename $${yamlschema_filename} .schema.yaml); \
			jsonschema_filename=$${basefilename}.schema.json; \
			go_filename=$${basefilename}.go; \
			ts_filename=$${basefilename}.d.ts; \
			echo "Generating $$jsonschema_filename for $${folder}"; \
			yq eval --output-format=json $${yamlschema_filename} > $(SCHEMA_DIR)/$${folder}/json/$${jsonschema_filename}; \
			echo "Generating $${go_filename} for $${folder}"; \
			gojsonschema -p $${folder} $(SCHEMA_DIR)/$${folder}/json/$${jsonschema_filename} > $(GODIR)/$${folder}/$${go_filename}; \
			echo "Generating $${ts_filename} for $${folder}"; \
			# docker run --rm -it -v $(SCHEMA_DIR)/$${folder}/json:/home node:alpine npx --yes json-schema-to-typescript --input /home/$${jsonschema_filename} --output $${ts_filename}; \
			json2ts --input $(SCHEMA_DIR)/$${folder}/json/$${jsonschema_filename} --output $(TSDIR)/$${folder}/$${ts_filename}; \
		done; \
	done

install:
	@for tool in $(TOOLS); do \
		go install $$tool; \
	done; \
	npm install -g json-schema-to-typescript
