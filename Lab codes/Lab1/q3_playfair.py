def create_matrix(key):
    key = key.upper().replace("J", "I")
    matrix = []

    used = []

    for ch in key:
        if ch not in used:
            used.append(ch)

    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in used:
            used.append(ch)

    for i in range(5):
        matrix.append(used[i*5:(i+1)*5])

    return matrix

def position(matrix, ch):
    if ch == 'J':
        ch = 'I'
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == ch:
                return i, j

def prepare(text):
    text = text.upper().replace(" ", "").replace("J","I")

    result = ""
    i = 0

    while i < len(text):
        a = text[i]
        if i+1 == len(text):
            b = 'X'
            i += 1
        else:
            b = text[i+1]
            if a == b:
                b = 'X'
                i += 1
            else:
                i += 2
        result += a+b

    return result

def encrypt(text, matrix):
    text = prepare(text)

    cipher = ""

    for i in range(0,len(text),2):

        a,b=text[i],text[i+1]

        r1,c1=position(matrix,a)
        r2,c2=position(matrix,b)

        if r1==r2:
            cipher+=matrix[r1][(c1+1)%5]
            cipher+=matrix[r2][(c2+1)%5]

        elif c1==c2:
            cipher+=matrix[(r1+1)%5][c1]
            cipher+=matrix[(r2+1)%5][c2]

        else:
            cipher+=matrix[r1][c2]
            cipher+=matrix[r2][c1]

    return cipher

matrix=create_matrix("GUIDANCE")

cipher=encrypt("The key is hidden under the door pad",matrix)

print("Matrix")
for row in matrix:
    print(row)

print(cipher)