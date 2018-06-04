all:
	sh version.sh && mkdir -p build && cd build && cmake ../ && make && cd ../
	@echo "make finish"
clean:
	cd build && make clean
	@echo "clean finish"
