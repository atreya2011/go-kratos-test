FROM golang:alpine

RUN apk add --no-cache git bash && \
  sed -i 's/bin\/ash/bin\/bash/g' /etc/passwd

# wait-for-it service is installed to wait for postgres service to start
ADD https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh /usr/local/bin

RUN chmod 755 /usr/local/bin/wait-for-it.sh && \
  # Get reflex for watching changes in all files
  go install github.com/cespare/reflex@latest

WORKDIR /src
COPY . /src

EXPOSE 4455

CMD wait-for-it.sh -t 30 auth-db:5432 -- sh -c "reflex -sr '(\.go$|go\.mod|\.html$)' go run main.go"
