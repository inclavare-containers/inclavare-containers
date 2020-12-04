crictl logs $(crictl ps | awk 'END{print $1}')
