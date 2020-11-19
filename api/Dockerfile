FROM fedora:33
LABEL Florian Dubourg <fldu@fldu.fr>

RUN dnf update -y && \
	dnf install -y python3-celery findutils fping zmap python-devel python-pip libpcap libpcap-devel python python3-uvicorn && \
	dnf clean all

RUN mkdir /app

COPY ./requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

COPY ./app /app

WORKDIR /app
RUN find . -name '*.sh' | while read file; do chmod +x ${file}; done
RUN python -m unittest -v 

ENTRYPOINT uvicorn main:api --reload --host 0.0.0.0
