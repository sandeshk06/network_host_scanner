FROM python:3.6
MAINTAINER Sandesh Kulkarni
RUN python -m pip install --upgrade pip && python -m pip install bcolors python-nmap
RUN apt-get update && apt-get install -y nmap    
RUN mkdir -p /opt/myapp/
COPY network_host_scan.py /opt/myapp/
WORKDIR /opt/myapp/
VOLUME data
ENTRYPOINT ["python","./network_host_scan.py"]
