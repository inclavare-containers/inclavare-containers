port=$((RANDOM + 1024))
while true;
do
	lsof -i:$port >/dev/null

	if [ $? -eq 1 ]; then
		echo $port
		break;
	else
		port=$((RANDOM + 1024))
		echo $port
	fi
done
