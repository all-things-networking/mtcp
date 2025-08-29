# Check if a filename was provided
if [ -z "$1" ]; then
  echo "Usage: $0 <filename>"
  exit 1
fi

filename="$1"

# Loop from 1 to 20
for i in {1..20}; do
  grep "Socket $i:" "$filename"
  echo "\n"
done
