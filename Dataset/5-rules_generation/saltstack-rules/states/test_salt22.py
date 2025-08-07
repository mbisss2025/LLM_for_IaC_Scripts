import sys

f = open(sys.argv[1], "rb")
byte = f.read(1)
while byte != b"":