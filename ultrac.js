card = new Card();
atr = card.reset(Card.RESET_COLD);

crypto = new Crypto();
deskey = new Key();

var KTL = new ByteString("49 45 4D 4B 41 45 52 42",HEX);
var KTR = new ByteString("21 4E 41 43 55 4F 59 46",HEX);
var LastKey = KTL.concat(KTR);

deskey.setComponent(Key.DES, LastKey);

resp = card.plainApdu(new ByteString("FF 00 00 00 02 1A 00", HEX));
print("Código SW: " + card.SW.toString(16));
print("respuesta: "+resp);

//Obtener respuesta
var aleCifrado = resp.right(8);
var VI = new ByteString("00 00 00 00 00 00 00 00", HEX);
var ale = crypto.decrypt(deskey, Crypto.DES_CBC, aleCifrado, VI);
print ("aleatorio: ", ale);

//Shift
var aleTerminal = crypto.generateRandom(8);
var aleShift = ale.concat(ale.bytes(0,1)).right(8);
var aleConc = aleTerminal.concat(aleShift);
var aleConcCifrado = crypto.encrypt(deskey, Crypto.DES_CBC, aleConc, aleCifrado); 

var envio = new ByteString("FF 00 00 00 11 AF", HEX);
resp = card.plainApdu(envio.concat(aleConcCifrado));
print("Código SW: " + card.SW.toString(16));
print("resp: " + resp);

var descifrado = crypto.decrypt(deskey,Crypto.DES_CBC, resp.right(8),aleConcCifrado.right(8));
var descifradoShift = descifrado.right(1).concat(descifrado.left(7));
print("comparar aleatorios: "+descifradoShift+"<----------->"+aleTerminal);



