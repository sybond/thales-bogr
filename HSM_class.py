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

import socket
from time import gmtime, strftime

BUFFER_SIZE = 1024
RST= chr(27) + "[0m"
AVL= chr(27) + "[36;1m"
LOG= chr(27) + "[37;1m"
HSMcmdHead = "TLBG"

def Exclude_Bigendian_Hdr(Adata):
	lenData = len(Adata)
        return chr(lenData >> 8)+chr(lenData & 255)+Adata
def ErrDesc(argument):
	desc = {
	"00": "No error",
	"01": "Verification failure or warning of imported key parity error",
	"02": "Key inappropriate length for algorithm",
	"04": "Invalid key type code",
	"05": "Invalid key length flag",
	"10": "Source key parity error",
	"11": "Destination key parity error or key all zeros",
	"12": "Contents of user storage not available. Reset, power-down or overwrite",
	"13": "Invalid LMK Identifier",
	"14": "PIN encrypted under LMK pair 02-03 is invalid",
	"15": "Invalid input data (invalid format, invalid characters, or not enough data provided)",
	"16": "Console or printer not ready or not connected",
	"17": "HSM not in the Authorised state, or not enabled for clear PIN output, or both",
	"18": "Document format definition not loaded",
	"19": "Specified Diebold Table is invalid",
	"20": "PIN block does not contain valid values",
	"21": "Invalid index value, or index/block count would cause an overflow condition",
	"22": "Invalid account number",
	"23": "Invalid PIN block format code",
	"24": "PIN is fewer than 4 or more than 12 digits in length",
	"25": "Decimalisation Table error",
	"26": "Invalid key scheme",
	"27": "Incompatible key length",
	"28": "Invalid key type",
	"29": "Key function not permitted",
	"30": "Invalid reference number",
	"31": "Insufficient solicitation entries for batch",
	"33": "LMK key change storage is corrupted",
	"39": "Fraud detection",
	"40": "Invalid checksum",
	"41": "Internal hardware/software error: bad RAM, invalid error codes, etc.",
	"42": "DES failure",
	"47": "Algorithm not licensed",
	"49": "Private key error, report to supervisor",
	"51": "Invalid message header",
	"65": "Transaction Key Scheme set to None",
	"67": "Command not licensed",
	"68": "Command has been disabled",
	"69": "PIN block format has been disabled",
	"74": "Invalid digest info syntax (no hash mode only)",
	"75": "Single length key masquerading as double or triple length key",
	"76": "Public key length error",
	"77": "Clear data block error",
	"78": "Private key length error",
	"79": "Hash algorithm object identifier error",
	"80": "Data length error. The amount of MAC data (or other data) is greater than or less than the expected amount.",
	"81": "Invalid certificate header",
	"82": "Invalid check value length",
	"83": "Key block format error",
	"84": "Key block check value error",
	"85": "Invalid OAEP Mask Generation Function",
	"86": "Invalid OAEP MGF Hash Function",
	"87": "OAEP Parameter Error"
	}
	return desc.get(argument,"Unknow error")

class ThalesBogr:
	def __init__(self, aIP, aPort):
		self.IP=aIP
		self.Port=aPort
		self.tcpcon=socket.socket(socket.AF_INET, socket.SOCK_STREAM)	
		print LOG+"ThalesBogor v"+AVL+"0.2"+RST+" - Copyright (c) 2014 Bondan Sumbodo\n"
	def connect(self):
		self.tcpcon.connect((self.IP, self.Port))
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
	def SendRawToHSM(self,aCmd):
		print RST+"Sending:"
		print AVL+aCmd.encode('hex')
		self.tcpcon.send(Exclude_Bigendian_Hdr(HSMcmdHead+aCmd))
		data=self.tcpcon.recv(BUFFER_SIZE)
		print RST+"Response:"
		print AVL+data[6:].encode('hex'),RST
	def GenPINOffset(self,CARD_NUM):
		print RST+"Card"+AVL,CARD_NUM
		self.GetClearPINFromPINOffset(CARD_NUM[len(CARD_NUM)-13:len(CARD_NUM)-1],"U35EB1B1605CC1DAC6017E46457EB28D6","111111FFFFFF","F93900465534BECA",6,CARD_NUM[len(CARD_NUM)-16:len(CARD_NUM)-6]+"N"+CARD_NUM[len(CARD_NUM)-1:len(CARD_NUM)])
	def GetClearPINFromPINOffset(self,AccNum,PVK,PINOffset,DecTable,ChkLength,PINValidation):
		print RST+"Get Clear PIN From PIN Offset"
		print RST+"AccountNumber"+AVL,AccNum,RST+"PINValidation"+AVL,PINValidation
		self.tcpcon.send(self.Exclude_Bigendian_Hdr(self.thales_EE_DeriveIBM3624PIN(AccNum,PVK,PINOffset,DecTable,ChkLength,PINValidation)))
		data=self.tcpcon.recv(BUFFER_SIZE)
		self.tcpcon.send(self.Exclude_Bigendian_Hdr(self.thales_NG_GetClearPIN(AccNum,data[10:])))
		data=self.tcpcon.recv(BUFFER_SIZE)
		self.thales_NG_Response(data)
		print RST+"Clear PIN:"+AVL,data[10:16]
	def removeNPC(self,text):
		return ''.join([i if ord(i) < 128 else '~' for i in text])
	def GenPinblockFromClear(self,ClearPIN,CARD_NUM,DestZPK):
		PINF=(ClearPIN+"FFFFFF")[0:7]
		AccNum=CARD_NUM[len(CARD_NUM)-13:len(CARD_NUM)-1]
		self.tcpcon.send(Exclude_Bigendian_Hdr(HSMcmdHead+"BA"+PINF+AccNum))
		data=self.tcpcon.recv(BUFFER_SIZE)
		if (data[8:10] == '00'):
			PINuLMK=data[10:17]
			#print RST+"PINuLMK:",AVL+PINuLMK
			self.tcpcon.send(Exclude_Bigendian_Hdr(HSMcmdHead+"JG"+DestZPK+"01"+AccNum+PINuLMK))
			data=self.tcpcon.recv(BUFFER_SIZE)
			if (data[8:10] == '00'):
				print RST+"Clear PIN:",AVL+ClearPIN,RST+"PINuLMK:",AVL+PINuLMK,RST+"PIN block:",AVL+data[10:]
			else:
				print RST+"Translate PIN to ZPK failed! HSM response:",AVL+ErrDesc(data[8:]),data[8:]
		else:
			print RST+"GenPinblockFromClear! HSM response:",AVL+ErrDesc(data[8:])
		print RST
	def selftest(self):
		self.tcpcon.send(Exclude_Bigendian_Hdr(HSMcmdHead+"NC"))
		AResponse=self.tcpcon.recv(BUFFER_SIZE)
		print LOG+"HSM Information"
		print RST+"IP:"+AVL,self.IP
		print RST+"Port:"+AVL,self.Port
		if (AResponse[8:10] == '00'):
			print RST+"LMK check value:"+AVL,AResponse[10:26]
			print RST+"Firmware number:"+AVL,AResponse[26:]
		print RST
