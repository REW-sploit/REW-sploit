#
# To Build:
#       sudo docker build -t rew-sploit/rew-sploit .
#
# To Run:
#       sudo docker run --rm -it --name rew-sploit -v /tmp:/tmp rew-sploit/rew-sploit
#
FROM parrotsec/core:latest

ENV DEBIAN_FRONTEND=noninteractive

# Install 
RUN apt-get update -y && \ 
    apt-get install -y python3-dev python3-pip python3-virtualenv sudo git && \
    apt-get install -y swig libssl-dev python3-yara libyara4 yara libpcap0.8-dev tcpdump
    
RUN ln -s /usr/bin/python3 /usr/bin/python

RUN cd /opt && \
    git clone https://github.com/REW-sploit/REW-sploit.git && \
    cd REW-sploit && \
    pip3 install -r requirements.txt && \
    ./apply_patch.py -f

# Clean up
RUN apt-get autoremove -y && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN ln -s /usr/local/lib/python3.9/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so
RUN echo "cd /opt/REW-sploit && ./rew-sploit.py" > /start.sh
RUN chmod 755 /start.sh

# Start 
CMD /start.sh

