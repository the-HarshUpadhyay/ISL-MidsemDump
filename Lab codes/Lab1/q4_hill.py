import numpy as np

key = np.array([[3,3],
                [2,7]])

text = "We live in an insecure world"

text = text.replace(" ","").upper()

if len(text)%2==1:
    text+="X"

cipher=""

for i in range(0,len(text),2):

    pair=np.array([[ord(text[i])-65],
                   [ord(text[i+1])-65]])

    result=np.dot(key,pair)%26

    cipher+=chr(result[0][0]+65)
    cipher+=chr(result[1][0]+65)

print(cipher)