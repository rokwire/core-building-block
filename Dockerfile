FROM golang:latest 
RUN mkdir /core-app
WORKDIR /core-app
# Copy the source from the current directory to the Working Directory inside the container
COPY . .
RUN make
EXPOSE 80
CMD ["./bin/core-building-block"]