if [ -z "$1" ]; then
    echo "Usage: $0 <upper_bound>"
    exit 1
fi

upper_bound=$1

./epwget 10.7.0.5/3.txt 2000 -n 0 -c 50 -f epwget-multiprocess.conf
for ((i=1; i<=upper_bound; i++)); do
    echo "Core $i"
    ./epwget 10.7.0.5/16k.txt 100 -n $i -c 10 -f epwget-multiprocess.conf
done

