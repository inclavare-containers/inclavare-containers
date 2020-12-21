sleep 30
crictl logs $(crictl ps | awk 'END{print $1}')
