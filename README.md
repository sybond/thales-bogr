## thales-bogr: Thales Bogor

Is a pyhton script to provide a tool to test your command against Thales HSM / Racal. A class called `ThalesBogr` in `HSM_class.py` is introduced to handle your basic needs of sending a trial host command to Thales HSM. 

Currently support following preformatting function to construct a host command:

1. EE Derive IBM3624 PIN
2. NG Get Clear PIN
3. JG Translate PIN under LMK to ZPK
4. JA Generate Random PIN
5. DE Generate IBM3624 PIN offset

Other host command can fully supported by self-formatting and send using `SendRawToHSM` function.

Sample usage:
```
test = ThalesBogor("192.168.0.22",9000)  // Create and set HSM class to use 192.168.0.22:9000
test.connect()                           // Initialize connection
test.SendRawToHSM("NC")                  // Sending custom command to HSM; ie. "NC"
test.disconnect()                        // Close connection

```

Output of this script:
```
ThalesBogr v0.1 - Copyright (c) 2014 Bondan Sumbodo

HSM Information
IP: 192.168.0.22
Port: 9000
LMK check value: 2686040000000000
Firmware number: 9999-1234

Sending: NC
Response: ND0026860400000000009999-1234
```
