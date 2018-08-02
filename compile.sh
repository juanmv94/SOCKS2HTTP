g++ -c -O3 main.cpp
g++ -c -O3 jsocket.cpp
g++ -c -O3 jssocket.cpp

g++ -s -o SOCKS2HTTP.out main.o jsocket.o jssocket.o -lpthread

rm *.o
