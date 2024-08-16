all: install run

install:
	pip3 install -r requirements.txt

clean:
	rm -rf src/__pycache__
	rm -rf assets

setup:
	make clean
	make install
	python3 src/data-setup.py

run:
	uvicorn src.voting-service-api:app --reload --port 8001