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

#!/usr/bin/env python
import socket
from time import gmtime, strftime

BUFFER_SIZE = 1024
#RST= ""
#AVL= ""
#LOG= ""
RST= chr(27) + "[0m"
AVL= chr(27) + "[36;1m"
LOG= chr(27) + "[37;1m"

class ThalesBogr:
	def __init__(self, aIP, aPort):
		self.IP=aIP
		self.Port=aPort
		self.tcpcon=socket.socket(socket.AF_INET, socket.SOCK_STREAM)	
		self.HSMcmdHead = "TLSB"
		print LOG+"\n\nThalesBogor v"+AVL+"0.1"+RST+" - Copyright (c) 2014 Bondan Sumbodo\n"
	def connect(self):
		self.tcpcon.connect((self.IP, self.Port))
		self.tcpcon.send(self.Exclude_Bigendian_Hdr(self.HSMcmdHead+"NC"))
		self.print_HSM(self.tcpcon.recv(BUFFER_SIZE))
	def disconnect(self):
		self.tcpcon.close()
	def Log(self, aTxt):
		print strftime("%Y-%m-%d %H:%M:%S", gmtime()),aTxt
		
	def thales_EE_DeriveIBM3624PIN(self,AccNum,PVK,PINOffset,DecTable,ChkLength,PINValidation):
		print LOG+"Derive a PIN Using the IBM Method"
		print RST+"Account Number:"+AVL,AccNum
		print RST+"PVK:"+AVL,PVK
		print RST+"Decimalisation Table:"+AVL,DecTable
		print RST+"The minimum PIN length:"+AVL,ChkLength
		print RST+"PIN Validation Data:"+AVL,PINValidation
		print RST+"PIN Offset:"+AVL,PINOffset,"\n"+RST
		return HSMcmdHead+"EE"+PVK+PINOffset+"%02d" % ChkLength+AccNum+DecTable+PINValidation
	def thales_EE_Response(self,AResponse):
		print LOG+"Derive a PIN Using the IBM Method Response"
		print RST+"Response:"+AVL,AResponse[8:10]
		if (AResponse[8:10] == '00'):
			print RST+"Unparsed:"+AVL,AResponse[10:]
		print "\n"+RST	
	def thales_NG_GetClearPIN(self,AccNum,PINuLMK):
		print LOG+"Decrypt an Encrypted PIN"
		print RST+"Account Number:"+AVL,AccNum
		print RST+"PIN under LMK:"+AVL,PINuLMK,"\n"+RST
		return HSMcmdHead+"NG"+AccNum+PINuLMK
	def thales_NG_Response(self,AResponse):
		print LOG+"Decrypt an Encrypted PIN Response"
		print RST+"Response:"+AVL,AResponse[8:10]
		if (AResponse[8:10] == '00'):
			print RST+"Clear PIN:"+AVL,AResponse[10:16]
			print RST+"Reference number:"+AVL,AResponse[17:]
		print "\n"+RST
	def thales_JG_TranslatePIN_LMKtoZPK(self,ZPK,PINfmt,AccNum,PINuLMK):
		print LOG+"Translate a PIN from LMK to ZPK Encryption"
		print RST+"Destination ZPK:"+AVL,ZPK
		print RST+"PIN block format code:"+AVL,"%02d" % PINfmt
		print RST+"Account Number:"+AVL,AccNum
		print RST+"PIN under LMK:"+AVL,PINuLMK,"\n"+RST
		return HSMcmdHead+"JG"+ZPK+"%02d" % PINfmt+AccNum+PINuLMK
	def thales_JG_Response(self,AResponse):
		print LOG+"Translate a PIN from LMK to ZPK Encryption Response"
		print RST+"Response:"+AVL,AResponse[8:10]
		if (AResponse[8:10] == '00'):
			print RST+"PIN block:"+AVL,AResponse[10:]
		print "\n"+RST
	def thales_JA_genRandomPIN(self,PAN, PINLength):
		print LOG+"Generate a Random PIN"
		print RST+"PAN:"+AVL,PAN
		print RST+"PIN length:"+AVL,PINLength,"\n"+RST
		return HSMcmdHead+"JA"+PAN+"%02d" % PINLength
	def thales_JA_Response(self,AResponse):
		print LOG+"Generate a Random PIN Response"
		print RST+"Response:"+AVL,AResponse[8:10]
		if (AResponse[8:10] == '00'):
			print RST+"PIN under LMK:"+AVL,AResponse[10:],"\n"+RST
	def thales_DE_genIBMPIN(self,PVK,PINuLMK,ChkLength,AccNum,DecTable,PINValidation):
		print LOG+"Generate an IBM PIN Offset"
		print RST+"PVK:"+AVL,PVK
		print RST+"PIN under LMK:"+AVL,PINuLMK
		print RST+"The minimum PIN length:"+AVL,ChkLength
		print RST+"Account Number:"+AVL,AccNum
		print RST+"Decimalisation Table:"+AVL,DecTable
		print RST+"PIN Validation Data:"+AVL,PINValidation,"\n"+RST
		return HSMcmdHead+"DE"+PVK+PINuLMK+"%02d" % ChkLength+AccNum+DecTable+PINValidation
	def thales_DE_Response(self,AResponse):
		print LOG+"Generate an IBM PIN Offset Response"
		print RST+"Response:"+AVL,AResponse[8:10]
		print RST+"PIN Offset:"+AVL,AResponse[10:],"\n"+RST
	def Exclude_Bigendian_Hdr(self,Adata):
		lenData = len(Adata)
		return chr(lenData >> 8)+chr(lenData & 255)+Adata
	def print_HSM(self,AResponse):
		print LOG+"HSM Information"
		print RST+"IP:"+AVL,self.IP
		print RST+"Port:"+AVL,self.Port
		if (AResponse[8:10] == '00'):
			print RST+"LMK check value:"+AVL,AResponse[10:26]
			print RST+"Firmware number:"+AVL,AResponse[26:]
		print RST
	def SendRawToHSM(self,aCmd):
		print RST+"Sending:"+AVL,aCmd
		self.tcpcon.send(self.Exclude_Bigendian_Hdr(self.HSMcmdHead+aCmd))
		data=self.tcpcon.recv(BUFFER_SIZE)
		print RST+"Response:"+AVL,data[6:],RST
	def GenPINOffset(self,CARD_NUM):
		print "Card",CARD_NUM
		GetClearPINFromPINOffset(CARD_NUM[len(CARD_NUM)-13:len(CARD_NUM)-1],"U35EB1B1605CC1DAC6017E46457EB28D6","111111FFFFFF","F93900465534BECA",6,CARD_NUM[len(CARD_NUM)-16:len(CARD_NUM)-6]+"N"+CARD_NUM[len(CARD_NUM)-1:len(CARD_NUM)])
	def GetClearPINFromPINOffset(self,AccNum,PVK,PINOffset,DecTable,ChkLength,PINValidation):
		print "Get Clear PIN From PIN Offset",AccNum,PINValidation
		self.tcpcon.send(Exclude_Bigendian_Hdr(thales_EE_DeriveIBM3624PIN(AccNum,PVK,PINOffset,DecTable,ChkLength,PINValidation)))
		data=self.tcpcon.recv(BUFFER_SIZE)
		self.tcpcon.send(Exclude_Bigendian_Hdr(thales_NG_GetClearPIN(AccNum,data[10:])))
		data=self.tcpcon.recv(BUFFER_SIZE)
		thales_NG_Response(data)
		print RST+"Clear PIN:"+AVL,data[10:16]
