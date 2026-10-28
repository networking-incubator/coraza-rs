FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY backend.go .
RUN CGO_ENABLED=0 go build -o /backend ./backend.go

FROM scratch
COPY --from=build /backend /backend
ENTRYPOINT ["/backend"]
