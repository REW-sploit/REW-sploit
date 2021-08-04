#
# To Build:
#       sudo docker build -t rew-sploit/rew-sploit .
#
# To Run:
#       sudo docker run --rm --name rew-sploit -v /tmp:/tmp rew-sploit/rew-sploit
#
FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

# Install 
RUN apt-get update -y && \ 
    apt-get install -y python3-dev python3-pip python3-virtualenv sudo git
    
RUN git clone https://github.com/REW-sploit/REW-sploit.git && \
    cd REW-sploit && \
    pip3 install -r requirements.txt && \
    ./apply_patch -f

# Clean up
RUN apt-get autoremove -y && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Start 
CMD ["./rew-sploit"]
