//MIFARE ULTRALIGHT C AUTHENTICATION

card = new Card();
atr = card.reset(Card.RESET_COLD);

crypto = new Crypto();
deskey = new Key();

initialIV = new ByteString("00 00 00 00 00 00 00 00", HEX);
//cardKey          = new ByteString("BREAKMEIFYOUCAN!", ASCII);
//terminalKey      = new ByteString("IEMKAERB!NACUOYF", ASCII);
terminalKeyLeft  = new ByteString("49 45 4D 4B 41 45 52 42", HEX);
terminalKeyRight = new ByteString("21 4E 41 43 55 4F 59 46", HEX);
terminalKey      = terminalKeyLeft.concat(terminalKeyRight);

deskey.setComponent(Key.DES, terminalKey);

//==== AUTHENTICATION REQUEST FROM TERMINAL ====
getChallengeCmdApdu = new ByteString("FF 00 00 00 02 1A 00", HEX);

resp = card.plainApdu(getChallengeCmdApdu);
print("Código SW: " + card.SW.toString(16));
print("resp: " + resp);

//==== CALCULATE AUTHENTICATION REQUEST RESPONSE FROM CARD ====
encryptedRndCard = resp.right(8);
rndCard = crypto.decrypt(deskey, Crypto.DES_CBC, encryptedRndCard, initialIV);
print ("RndCard: ", rndCard);

//==== ENCRYPT AND SEND RANDOM FROM TERMINAL --> AUTHENTICATE TERMINAL ====
rndTerm = crypto.generateRandom(8);
rndCardShifted = rndCard.concat(rndCard.bytes(0,1)).right(8);
token = rndTerm.concat(rndCardShifted);
encryptedToken = crypto.encrypt(deskey, Crypto.DES_CBC, token, encryptedRndCard); 

sendTerminalResponseApdu = new ByteString("FF 00 00 00 11 AF", HEX);
resp = card.plainApdu(sendTerminalResponseApdu.concat(encryptedToken));
print("Código SW: " + card.SW.toString(16));
print("resp: " + resp);

//==== VERIFY TERMINAL AUTHENTICATION IS OK ====
authenticationState = resp.bytes(0,1);
receivedEncryptedToken = resp.right(8);

assert(authenticationState.toString() == "00") //If not 00 -> Failed Authentication, exit

//==== DECRYPT RANDOM FROM CARD --> AUTHENTICATE CARD ====
newIV = encryptedToken.right(8);
token = crypto.decrypt(deskey, Crypto.DES_CBC, receivedEncryptedToken, newIV);
tokenShiftedRight = token.right(1).concat(token.left(7));
assert(tokenShiftedRight.equals(rndTerm));
print ("received token shifted:    ", tokenShiftedRight);
print ("generated terminal random: ", rndTerm);




