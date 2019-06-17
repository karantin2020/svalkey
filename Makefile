

check:
	rm .inner/*; \
	date > .inner/go-carpet.out; go-carpet -summary >> .inner/go-carpet.out; \
	gosec -fmt=json -out=.inner/gosec_res.json ./...

test:
	go test -v --race -count=1 ./...