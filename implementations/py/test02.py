#!/Library/Frameworks/Python.framework/Versions/3.7/bin/python3
#
# Copyright (C) 2019 Mike Hummel (mh@mhus.de)
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


from Crypto.Cipher import Blowfish
from struct import pack

bs = Blowfish.block_size
key = b'asdfghjkl'
ciphertext = b'MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAM/NIqP7cvUpBnT67AsbEdInIF9KlFiklgzEF4UP1vN1wTSnHuVzQD/DNYBtYRvQOg6sr+usGV2DrnsAn1lgatwlNV3ethTOSPsLfv8HA//LofTW2ZGZ0D4CsQZBWgjmHRppVYb+2DUiVZG2IPo4SWAhtfmwNuVMDWHq5oKFxauVAgMBAAECgYBSbhA4tk0ivRRnoQWzXhiSoZyw0DfKdfdjtwGRcfgVeXebuFOEN1ScNoZpnHnx+4acPZpHRWyGcO7sshGD9cBNPqP2hvp9d+YvH3JOczO+D3xnSlfnMii0XR7eTaF32+T73rB4G/cQ8+Gp9IeoZwrj60sa4WZUrOuvUeH4NQEIIQJBAOgi0iM973ZntKbeJBoEeIRX0nYIz5qGytXyeZJPFegUhX0Ljf9wQD9x8Zwm+8AhHmGyFasb1Cw/u4j7ATOnl90CQQDlKeRg0KOZ9W6h+4o2XlDcL5aUJcEZulWGvIbUXcKUWBdQbrwMbCb/6bPpjScQFpTR6tZla4S9IULKkHJGPUMZAkEA42sBra8Gw1xUGkp02dxZaWZUdHirUnsNik6TlafPEV/RazD/uylwd/ecOVvjtVV82z9JhSmtUnBZvJgTlFRzLQJBALej2HWU/GWV/nAkCOAEuLuaDwrtLk8VuQ/d6BYqhJEn/pbgBiXWTXJqr1gLWzBTSDLoA6MGhDqjesik9E5BLZECQFDVDPjE10MbqVvkFMRPcPJvECBn44TFeg2MseEAkQHVgbfuvVgZ3eX2nc3uzqbflCfgi1F1lINBeoJQIb4eexQ='
iv = ciphertext[:bs]
ciphertext = ciphertext[bs:]

cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
msg = cipher.decrypt(ciphertext)

last_byte = msg[-1]
msg = msg[:- (last_byte if type(last_byte) is int else ord(last_byte))]
print(repr(msg))
