FROM golang:1.13 as golang

# Set go bin which doesn't appear to be set already.
ENV GOBIN /go/bin
ARG BUILD_ID
ENV BUILD_IMAGE=$BUILD_ID
ENV GO111MODULE=off
RUN echo $SCRIPT
ENV SCRIPT_NAME=$SCRIPT
RUN echo $SCRIPT_NAME

# build directories
ADD . /go/src/git.xenonstack.com/akirastack/continuous-security-deployments
WORKDIR /go/src/git.xenonstack.com/akirastack/continuous-security-deployments

RUN go install git.xenonstack.com/akirastack/continuous-security-deployments
EXPOSE 8000

# new build stage started and copy artifacts from previous stage
#FROM python:3.7-stretch
FROM nikolaik/python-nodejs:python3.6-nodejs13-stretch
ARG BUILD_ID
ENV BUILD_IMAGE=$BUILD_ID
RUN pip install anytree argcomplete tabulate

# install dependency packages
RUN apt update; apt-get install -y nmap whois dnsutils ldnsutils ldnsutils bsdmainutils netcat
#RUN npm install wappalyzer -g --unsafe-perm

# clone git repository
RUN git clone https://github.com/meliot/shcheck.git $HOME/projects/security/tools/shcheck; git clone https://github.com/nixcraft/domain-check-2.git $HOME/projects/security/tools/domain-check ; wget https://github.com/drwetter/testssl.sh/archive/refs/tags/3.0.5.tar.gz ; tar xvf 3.0.5.tar.gz -C $HOME/projects/security/tools/ ; wget https://raw.githubusercontent.com/nixcraft/domain-check-2/master/domain-check-2.sh ; mv domain-check-2.sh /usr/local/bin/domain-check-2.sh ; chmod +x /usr/local/bin/domain-check-2.sh 
RUN cp -r $HOME/projects/security/tools/testssl.sh-3.0.5  $HOME/projects/security/tools/testssl.sh

RUN git clone https://github.com/koenbuyens/securityheaders $HOME/projects/security/tools/securityheaders

#create folder to copy code from previous stage and executable from previous stage
RUN mkdir -p /go/src/git.xenonstack.com/akirastack/continuous-security-deployments; mkdir -p /go/bin

#set working directory
WORKDIR /go/src/git.xenonstack.com/akirastack/continuous-security-deployments

#copy code from previous stage
COPY --from=golang  /go/src/git.xenonstack.com/akirastack/continuous-security-deployments /go/src/git.xenonstack.com/akirastack/continuous-security-deployments

#copy executable file from previous stage
COPY --from=golang /go/bin/continuous-security-deployments  /go/bin/

#clonning scripts
RUN git config --global http.sslVerify false
RUN git clone https://gitlab-ci-token:LisfzisY1Ly2oxmWGiBJ@git.xenonstack.com/devops/web-security.git -b develop --single-branch tools/
RUN cp -r /go/src/git.xenonstack.com/akirastack/continuous-security-deployments/tools/* $HOME/projects/security/tools/
RUN mv /go/src/git.xenonstack.com/akirastack/continuous-security-deployments/tools /go/src/git.xenonstack.com/akirastack/continuous-security-deployments/scripts

#install domain-check2 tool
#RUN wget https://raw.githubusercontent.com/nixcraft/domain-check-2/master/domain-check-2.sh ; cp -vf domain-check-2.sh /usr/local/bin/domain-check-2.sh ; chmod +x /usr/local/bin/domain-check-2.sh

#liston on port
EXPOSE 8000
