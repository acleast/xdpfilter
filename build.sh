
XDP=pkg/xdp/prog/

echo "begining compile xdp"

clang -O2 -target bpf -c $XDP/xdp.c -o $XDP/xdp.o -D__KERNEL__

echo "compile xdp completely"

echo "beining build go program"

go build main.go

echo "build completely!"
