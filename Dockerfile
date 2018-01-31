FROM python:2.7

RUN mkdir -p /app
COPY *.py droidstatx.config requirements.txt /app/
WORKDIR /app

# update and install jre
RUN apt-get update \ 
    && apt-get -y dist-upgrade \
    && apt-get -y install default-jre \
    && apt-get autoremove -yqq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


RUN cd /app/ \
    && python install.py \
    && chmod u+x /app/droidstatx.py

CMD ["python","/app/droidstatx.py"]
