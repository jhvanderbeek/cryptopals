import helper as h
from multiprocessing import Pool

def findbesttranslation(ciphertext):
    # cycle through all keys and return the one with the lowest score" 
    bestscore = 50*len(ciphertext)
    besttranslation = h.singlecharxor(ciphertext, 0)
    bestkey = 0
    for key in range(256):
        possplain = h.singlecharxor(ciphertext, key)
        score = h.score(possplain)
        if score < bestscore:
            bestscore = score
            besttranslation = possplain
            bestkey = key
    
    return besttranslation, bestscore, key

filepath = "/home/daniel/Projects/cryptopals/set1/4.txt"
# Read in the ciphertexts
with open(filepath) as f:
    p = Pool(4)
    ciphers = f.read()
    ciphers = ciphers.split('\n')
    # Turn ciphers into byte objects
    cipherarrs = p.map(h.hexstrtobytes, ciphers)

    besttranslations = p.map(findbesttranslation, cipherarrs)

scores = [a[1] for a in besttranslations]
bestbestscore = min(scores)

bestbest = scores.index(bestbestscore)
bestbesttranslation, bestbestscore, bestbestkey = besttranslations[bestbest]


print(bytes(bestbesttranslation), bestbestkey)