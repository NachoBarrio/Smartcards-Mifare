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
// prueba aleatorio obtenido


var RndBcifrado = resp.right(8);
//Obtener respuesta
var VI = new ByteString("00 00 00 00 00 00 00 00", HEX);
var RndB = crypto.decrypt(deskey, Crypto.DES_CBC, RndBcifrado, VI);
print ("RndB: ", RndB);

//Shift
var RndT = crypto.generateRandom(8);
var RndBprima = RndB.concat(RndB.bytes(0,1)).right(8);
var aleConc = RndT.concat(RndBprima);

var aleConcCifrado = crypto.encrypt(deskey, Crypto.DES_CBC, aleConc, RndBcifrado); 
print("aleConcCifrado: "+aleConcCifrado);

var envio = new ByteString("FF 00 00 00 11 AF", HEX);
resp = card.plainApdu(envio.concat(aleConcCifrado));
print("Código SW: " + card.SW.toString(16));
print("resp: " + resp);

//prueba de verificacion
var pruebaVer = resp.bytes(0,1);
print("la autenticación ha sido: "+pruebaVer.toString());

//calculo del terminal
var descifrado = crypto.decrypt(deskey,Crypto.DES_CBC, resp.right(8),aleConcCifrado.right(8));
print("descifrado: "+descifrado);
var descifradoShift = descifrado.right(1).concat(descifrado.left(7));
print("comparar aleatorios: "+descifradoShift+"<----------->"+RndT);

// -------------------   escribir páginas -------------------- 
//Escribir en el bloque 0x04
var msg = new ByteString("UNOC",ASCII);
var lng = msg.length.toString(HEX);
msgConcat = new ByteString(msg,HEX);
if(msg.length < 16){
 lng = "0"+msg.length
}
resp = card.plainApdu(new ByteString("FF D6 00 04"+lng, HEX).concat(msg));
print("Código SW: " + card.SW.toString(16));
//Escribir en el bloque 0x05
var msg = new ByteString("HT01",ASCII);
var lng = msg.length.toString(HEX);
msgConcat = msgConcat.concat(msg);
if(msg.length < 16){
 lng = "0"+msg.length
}
resp = card.plainApdu(new ByteString("FF D6 00 05"+lng, HEX).concat(msg));
print("Código SW: " + card.SW.toString(16));
//Escribir en el bloque 0x06
var msg = new ByteString("E001",ASCII);
var lng = msg.length.toString(HEX);
msgConcat = msgConcat.concat(msg);
if(msg.length < 16){
 lng = "0"+msg.length
}
resp = card.plainApdu(new ByteString("FF D6 00 06"+lng, HEX).concat(msg));
print("Código SW: " + card.SW.toString(16));
//Escribir en el bloque 0x07
var msg = new ByteString("2606",ASCII);
var lng = msg.length.toString(HEX);
msgConcat = msgConcat.concat(msg);
if(msg.length < 16){
 lng = "0"+msg.length
}
resp = card.plainApdu(new ByteString("FF D6 00 07"+lng, HEX).concat(msg));
print("Código SW: " + card.SW.toString(16));
//Escribir en el bloque 0x08
var msg = new ByteString("1989",ASCII);
var lng = msg.length.toString(HEX);
msgConcat = msgConcat.concat(msg);
if(msg.length < 16){
 lng = "0"+msg.length
}
resp = card.plainApdu(new ByteString("FF D6 00 08"+lng, HEX).concat(msg));
print("Código SW: " + card.SW.toString(16));
//Escribir en el bloque 0x09
var msg = new ByteString("2503",ASCII);
var lng = msg.length.toString(HEX);
msgConcat = msgConcat.concat(msg);
if(msg.length < 16){
 lng = "0"+msg.length
}
resp = card.plainApdu(new ByteString("FF D6 00 09"+lng, HEX).concat(msg));
print("Código SW: " + card.SW.toString(16));
//Escribir en el bloque 0x0A
var msg = new ByteString("2018",ASCII);
var lng = msg.length.toString(HEX);
msgConcat = msgConcat.concat(msg);
if(msg.length < 16){
 lng = "0"+msg.length
}
resp = card.plainApdu(new ByteString("FF D6 00 0A"+lng, HEX).concat(msg));
print("Código SW: " + card.SW.toString(16));
//Escribir en el bloque 0x0B
var msg = new ByteString("0025",ASCII);
var lng = msg.length.toString(HEX);
msgConcat = msgConcat.concat(msg);
if(msg.length < 16){
 lng = "0"+msg.length
}
resp = card.plainApdu(new ByteString("FF D6 00 0B"+lng, HEX).concat(msg));
print("Código SW: " + card.SW.toString(16));

//calcular MAC
var KTML = new ByteString("00 01 02 03 04 05 06 07",HEX);
var KTMR = new ByteString("18 19 1A 1B 1C 1D 1E 1F",HEX);
//Lee el serial number de la tarjeta, para mifare ultralight. 07 es el numero de bytes del serial.
resp = card.plainApdu(new ByteString("FF CA 00 00 07", HEX));
print("SERIAL NUMBER: " + resp);
var serial = resp.concat(new ByteString("FF",HEX));
print(card.SW.toString(16));
print();
var KTMLR = KTML.concat(KTMR);
deskey.setComponent(Key.DES, KTMLR);
var claveTarjeta = crypto.encrypt(deskey,Crypto.DES_ECB,KTMLR);
deskey.setComponent(Key.DES,claveTarjeta);
var MACcifrado = crypto.encrypt(deskey, Crypto.DES_CBC, msgConcat, serial); 
var MAC = MACcifrado.right(8).left(4);
print("pintar mac: "+MAC);

//escribir MAC
//Escribir en el bloque 0x0C
var msg = MAC;
var lng = msg.length.toString(HEX);
if(msg.length < 16){
 lng = "0"+msg.length
}
resp = card.plainApdu(new ByteString("FF D6 00 0C"+lng, HEX).concat(msg));
print("Código SW: " + card.SW.toString(16));

//establecer restriciones
lng = "04";
resp = card.plainApdu(new ByteString("FF D6 00 2A"+lng, HEX).concat(new ByteString("04 00 00 00",HEX)));
print("Código SW: " + card.SW.toString(16));
resp = card.plainApdu(new ByteString("FF D6 00 2B"+lng, HEX).concat(new ByteString("00 00 00 00",HEX)));
print("Código SW: " + card.SW.toString(16));