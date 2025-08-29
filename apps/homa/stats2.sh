# Check if a filename was provided
if [ -z "$1" ]; then
  echo "Usage: $0 <filename>"
  exit 1
fi

filename="$1"

grep "MTP TCP closed" $filename | wc -l

echo "[0,9]"
grep "Stream .: MTP TCP closed" $filename | wc -l

for i in {1..9}; do
  echo ["$i"0, "$i"9]
  grep "Stream "$i".: MTP TCP closed" "$filename" | wc -l
done

for i in {1..9}; do
    for j in {1..9}; do
        echo ["$i""$j"0, "$i""$j"9]
        grep "Stream "$i""$j".: MTP TCP closed" "$filename" | wc -l
    done
done
