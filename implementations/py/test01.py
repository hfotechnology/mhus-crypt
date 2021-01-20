#
# Copyright (C) 2020 Mike Hummel (mh@mhus.de)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import blowfish
import base64

# https://github.com/jashandeep-sohi/python-blowfish

cipher = blowfish.Cipher(b'testit')

encrypted = 'jZm1l82bdMU8+nc6pt/C/E+isFlJyKvZtwcNR3aLAp7Y8xT3hqKzrtsjhn85KfaN8dR5hgFRTHaEzd/xRqQYC3xQu7U0jwl/LJCPMMC1BBdth/PvfuF5Qr6u/TLz1vl2ZkGXf6aoBx4LWhBONT/OkbGwjGrjdHVtzx1meSHJyGjY0rsc8+s2sMQsbAKwMA8ZCGDRrT9277R36nTaTOIbb+z9wJY7wh3kTZj4KpkXBQOIziB0BAQwXOIHXvGx95Nh31A8pCNS8voBz8wuIsOPKMKvYq7l+X5QthxySY3LXw/l2F5eH7d2sT/JFiljwtJzouhxfdAC5crfieMHYfN5frm0d+1cB1TMjkbVW505GZpauLXLQs9WA3CRK8t8vQDZJKPvr1CgYZZoylEPYwqF7W00rtbhBMX3+YtWE8qNUfo6OD3Cj23GYQnXVTLCJhxAizYX7sSLnkYNiH4HHkW187PNYda/fIHoybJ5jPzZ3nSVvKh/lNzetUoxAUHM0noqMTXGEhnQLN+dq/LTo7uJ5czasWu6nx2hEsmGTyRNvSsFbjLiqVlee4BbjgJVel/LFYIaWeLYtDZZwGBTS81pCTxU8gF3ksIQtiDesvyzBFBP9bHyu/aS8RvqGg2IeHZY0GZHtBygZMs++HnmJQ2QfGbQs6OuRnVEMgV5rI3WcAwrcz38/g4/4IR27TwISMubzRT1zFVaocklJ4TEucFgz0OU1euETa0xbStc/HPUBKrZt3+9w0sGmNzvXUnKzAoNtMMq7TIxJ4ik6jzYURWV7qKfyN+0Wk27nOaXlBPNPitvUYoSaygysK1CjaC2+PnCkpPaZA7Q0RQAZvboBynqEw=='
decrypted= 'MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANSu8ZR5hMNR0mWsbHMjZZLtqvbntEIGbnBRuq3O7VV/0h0EvByDFrReRPS1vZq/O9pcLmCmPcTKHLZlIEf/LilOThznd1o397uYXL7duL7k0h8qauU12rhBKEiryrlz6E3Fp5tB1T07Qz+1xcaDTq/gaHieN5BWZa/0l80DgCEbAgMBAAECgYArRaTVRpwieUVLdndiPbNu33hHYAEm5dQWeip3LoDPQoBncw0q5+j4ra1t9IQtNfdhiBvPgkNTBKQu4AhfXaXwVo/1W6rl1hBxCpQMjoDVOvyXBF++clMMV4YozyavFYQAN7kbs/cfWjlGo3Yls+WkyMro1JNKKA54Qa7h9VvG4QJBAOtu9EocdYLyz9FxOUiw8c0M1SX3C6g/LRfqZgC6SbKHHRiYzU3gUkrOpHM4RI/etrmLX2uht01bkthsyGdCeakCQQDnQzm/VRrUdkA7tL6N5nA2G8zIYiHupjSZ0LaZt88ruLRZK8SGWk1APBFljoWi5Amdv//63g9/ECyyXAVV0ucjAkBP5AvTpkqeEAVDXjeBGkJDQaqGwolbI20K44iPkKd3hG/0K83nMkrahbq6OorRg1LgLZJItMy93Gg9NtTebWlZAkEAocOiVzWeiNMWZy0sxXFVOGQFwHz0I0zbKmSV9bxfC8QtUtqMozXzJ2Vc/d7Nl31PRKsS0VYXHNghi7lWegwGZQJAX5kCc7KAwhWuiT8s4hxVIzIZZ/tKTC8g1Pxqc0PgDhGwAjrqjKUo6fomGoNp3mDK5hRtV5tZCgjICZrl16w88g=='
print(base64.b64decode(decrypted))
data_encrypted = base64.b64decode(encrypted)

print( "Len: %i" % len(data_encrypted) )
while len(data_encrypted) % 8 != 0:
    data_encrypted+=b'\x00'
print( "Len: %i" % len(data_encrypted) )

data_decrypted = bytearray(b"".join(cipher.decrypt_ecb(data_encrypted)))
print(data_decrypted)
while (data_decrypted[len(data_decrypted)-1] == 6):
    del data_decrypted[-1]

secret = base64.b64encode(data_decrypted)



print(secret)

