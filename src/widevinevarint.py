import sys

def WidevineVarInt(value):
    parts = [value % 128]
    value >>= 7
    while value:
        parts.append(value%128)
        value >>= 7

    for i in range(len(parts)-1):
        parts[i] |= (1<<7)
    varint = ''
    for x in parts:
        varint += chr(x)
    return varint

def unpackWidevineVarInt(value):
    parts = []
    for x in value:
        parts.append(ord(x))

    for i in range(len(parts)-1):
        parts[i] |= (1>>7)
        parts[i] = parts[i]%128

    varint = 0

    for i in reversed(parts):
        varint <<= 7
        varint += i
    return varint

init_data = int(sys.argv[1])
x = WidevineVarInt(init_data)
print x
print 'length of result = %d' % len(x)
y = unpackWidevineVarInt(x)
print y