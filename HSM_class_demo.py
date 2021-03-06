#!/usr/bin/env python
# The MIT License (MIT)
# 
# Copyright (c) 2014 Bondan Sumbodo
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Sample usage of ThalesBogr class

from HSM_class import *


#create ThalesBogr instance as hsm
hsm = ThalesBogr("10.99.30.181",9000)

#connect and perform selftest
hsm.connect()
hsm.selftest()

#hsm.GenPinblockFromClear("1111","6213440000001234","U741521AFC27713C2DC0989B1D0F25D6E")
#constructing NG command and send to HSM
hsm.SendRawToHSM(hsm.thales_NG_GetClearPIN("6213440000001234","9803479"))

#close connection
hsm.disconnect()
