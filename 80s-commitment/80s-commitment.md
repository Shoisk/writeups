# Information

We're presented with a website, the python running behind it, and are asked to rickroll the author:

![](web.png)

```
#Runs on python3.9 with Pycrypto 2.6.1 instead of pycryptodome ­Ъци that may save you some debugging time.
from flask import Flask
from flask import request
from Crypto import Random
from random import randint
from Crypto.PublicKey import ElGamal
import base64
import json
import os.path
import random
app = Flask(__name__)

key = None
if os.path.isfile('key.txt'):
    keydata = json.load(open('key.txt', 'r'))
    key = ElGamal.construct(keydata)
else:
    key = ElGamal.generate(1024, Random.new().read)
    json.dump([key.p, key.g, key.y, key.x], open('key.txt', 'w'))

def commit_id(id):
    return pow(key.g, int.from_bytes(base64.urlsafe_b64decode(id + '='), byteorder = 'big'), key.p)

flag = open('flag.txt').read()
ids = open('ids.txt').read().splitlines()
rick_id = commit_id('dQw4w9WgXcQ')

@app.route('/')
def norickplz():
    op = random.choice(ids)
    cid = commit_id(op)
    cenc = key.encrypt(cid, randint(1, key.p-1))
    open('reveal.txt', 'w').write(str(cenc[0]))
    return """
    <html>
        <body>
        I commit to a lot of 80s music, but don\'t you try to rickroll me!<br/>
        My public key: ({key_p}, {key_g}, {key_y})<br/>
        My commitment: {commit}<br/>
        Reveal:
            <form method="POST" action="/reveal/">
                <input name="commit"/>
                <button type="submit">Reveal!</button>
            </form>
        </body>
    </html>
    """.format(key_p = key.p, key_g = key.g, key_y = key.y, commit = cenc[1])

@app.route('/reveal/', methods=['POST'])
def reveal():
    if request.method == 'POST':
        alpha = int(open('reveal.txt', 'r').read())
        beta = int(request.form['commit'])
        my_id = key.decrypt((alpha, beta))
        video_id = [vid for vid in ids if commit_id(vid) == my_id]
        if my_id == rick_id:
            return """
            <html><body>
                    Aaah, you rickrolled me! here's the flag: {flag}<br/>
                    And here is the video you really wanted to see: <br/>
                    <iframe width="560" height="315" src="https://www.youtube.com/embed/dQw4w9WgXcQ" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
            </body></html>
            """.format(flag=flag)
        elif video_id:
            return """
            <html><body>
                    Here is your cheesy 80s music video, with the tag {video_id1}:<br/>
                    <iframe width="560" height="315" src="https://www.youtube.com/embed/{video_id2}" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
            </body></html>
            """.format(video_id1=video_id[0],video_id2=video_id[0])
        else:
            return """
            <html><body>
                    I'm very sorry, I couldn't find the cheesy 80s music you were looking for!
            </body></html>
            """
    else:
        return """
        <html><body>
                You wanted a reveal, but what did you want me to reveal?
        </body></html>
        """
if __name__ == "__main__":
    try:
        app.run(host='0.0.0.0', port=80)
    except:
        print("oh no")
```


The most important things to realize here, is that the video identifiers are converted to integers in the function `commit_id` and are then encrypted using ElGamal.

# On ElGamal

ElGamal is a very interesting form of encryption, in that it's homomorphic, meaning we can actually perform basic arithmetic on encrypted values. Which means in essence doing these two things would result in the same ciphertext: `enc(a)*enc(b) = enc(a+b)`. Note this is a simplication, we'll look at an actual formula in a second.

In ElGamal you encrypt by lifting some generator *g* to the power of your message and multiplying it with your public key modulo some large prime: <img src="https://render.githubusercontent.com/render/math?math=c = g^m \cdot k_p"> 
Because of the associative property of multiplication this also means that if we had some other message <img src="https://render.githubusercontent.com/render/math?math=m_2"> that we wanted to add to the encrypted message, we can do just that by multiplying it with *c* since <img src="https://render.githubusercontent.com/render/math?math=c%5Ccdot%20g%5E%7Bm_2%7D%20%3D%20g%5E%7Bm_2%7D%20%5Ccdot%20%28g%5Em%20%5Ccdot%20k_p%29%20%3D%20%28g%5E%7Bm_2%7D%20%5Ccdot%20g%5Em%29%20%5Ccdot%20k_p%20%3D%20g%5E%7Bm_2%2Bm%7D%20%5Ccdot%20k_p">

# The Solution
Since we can manipulate the encrypted data and know what it decrypts to, we can exploit the encryption itself, by just adding or subtracting from the actual message to achieve some other value when it's decrypted.

First let's find out what video id is currently linked on the website, we just paste the commitment on the website into the box and we get `YZUE4_PtOk0`. We also know from the python code that the ID we're supposed to end up with is `dQw4w9WgXcQ`. 
We can decode those to integers: `int.from_bytes(base64.urlsafe_b64decode(),  byteorder = 'big')` and we get
commit video: 7031531770305395277
rickroll vid: 8434178615911931332

This is great, since the rickroll video is a larget number, we can essentially just "add" the difference between the two to the encrypted message.
We find the diff: 8434178615911931332 - 7031531770305395277 = 1402646845606536055.
The commit_id function essentially just converts from base64 to an integer and then lifts the generator to the power of whatever integer the id converts to, so it forms g<sup>m</sup>. We can do the same thing with our diff: `add_value = pow(key.g, 1402646845606536055, byteorder = 'big'), key.p)`
All we need to now is multiply the commitment on the website with this value modulo key.p and we get our result:
114153471363479074732741039105221960382301474843192036667761822778390046362949147937010974352187924051138566688709481919076595890377917675589997277019951752217826288423674009060504483355327192007673834082989961616355740202775368749278232108690251816954353796675061222245233772155706998962416024925109459167366

After inputting this on the website we get the flag: DDC{4ldr1g_g1v3r_j3g_d1g_0p_3ll3r_n0g3T} 

# Script solution

All this put into a little script that just needs the video id and old commitment value to work:

```
import base64
from Crypto.PublicKey import ElGamal

# Dynamic from site
commitment = 138671835905098738723952832475433983495823314368245919510868375833590445395838275982499084035001561434700247723240535486386627096186739675025575325338218250692521623125155016559582028125766471170302314028958855796588183851461828229754843181952957852839698704015843548770193770126453610555328208796886608695123

keytuple = (171651487564665188709696071419453485395071661478962815543726294106018240905063215109668595489789996605360205665709272203829586629878234979355953282462961745069389037545035054232207660340222173839586890685127419728129664935083084059915287590870642102026331366475529208457259452436612905460819402026975569601899, 27305933566818278720696389534012959492649387746252108251770409919396275174057176634224305878634581806277044720415849682636085818092615674889056390082015679654921658340400858196943671854522774982673668016420578497559718448965162949499550758735528210054243289575125149360586547518514288700022584365578504751595, 14509018973801615346649023647605480116892698284934901793820718679493796698000753898221668659022601421988486699339068404468388106933045944721080609239218644336378600784755810851494467805584561029049044869164340724415833814070220331196859578505004220345685572994813155151967295398442102145775813982857405944710)

key = ElGamal.construct(keytuple)

rickrollid = 'dQw4w9WgXcQ'
web_id = 'YZUE4_PtOk0' #Dynamic from site

rickroll_int = int.from_bytes(base64.urlsafe_b64decode(rickrollid+'='), byteorder = 'big') 
web_int = int.from_bytes(base64.urlsafe_b64decode(web_id+'='), byteorder = 'big')


diff = rickroll_int - web_int
diff_commit = pow(key.g, diff, key.p)

new_commit = (commitment * diff_commit) % key.p

print(new_commit)
```