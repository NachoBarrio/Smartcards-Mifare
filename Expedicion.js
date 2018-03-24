
card = new Card();
atr = card.reset(Card.RESET_COLD);
//print(atr);
//constantes crifrado
var crypto = new Crypto();
var deskey = new Key();

//Lee el serial number de la tarjeta, para mifare ultralight. 07 es el numero de bytes del serial.
resp = card.plainApdu(new ByteString("FF CA 00 00 07", HEX));
print("SERIAL NUMBER: " + resp);
var serial = resp;
print(card.SW.toString(16));
print();

//Write paginas
//Escribir en el bloque 0x04
var msg = new ByteString("11SI",ASCII);
var lng = msg.length.toString(HEX);
if(msg.length < 16){
 lng = "0"+msg.length
}
resp = card.plainApdu(new ByteString("FF D6 00 04"+lng, HEX).concat(msg));
print("Código SW: " + card.SW.toString(16));
//Escribir en el bloque 0x05
var msg = new ByteString("EE01",ASCII);
var lng = msg.length.toString(HEX);
if(msg.length < 16){
 lng = "0"+msg.length
}
resp = card.plainApdu(new ByteString("FF D6 00 05"+lng, HEX).concat(msg));
print("Código SW: " + card.SW.toString(16));
//Escribir en el bloque 0x06
var msg = new ByteString("3131",ASCII);
var lng = msg.length.toString(HEX);
if(msg.length < 16){
 lng = "0"+msg.length
}
resp = card.plainApdu(new ByteString("FF D6 00 06"+lng, HEX).concat(msg));
print("Código SW: " + card.SW.toString(16));
//Escribir en el bloque 0x07
var msg = new ByteString("VD01",ASCII);
var lng = msg.length.toString(HEX);
if(msg.length < 16){
 lng = "0"+msg.length
}
resp = card.plainApdu(new ByteString("FF D6 00 07"+lng, HEX).concat(msg));
print("Código SW: " + card.SW.toString(16));
//Escribir en el bloque 0x08
var msg = new ByteString("0025",ASCII);
var lng = msg.length.toString(HEX);
if(msg.length < 16){
 lng = "0"+msg.length
}
resp = card.plainApdu(new ByteString("FF D6 00 08"+lng, HEX).concat(msg));
print("Código SW: " + card.SW.toString(16));
//Escribir en el bloque 0x09
var msg = new ByteString("2018",ASCII);
var lng = msg.length;
if(msg.length < 16){
 lng = "0"+msg.length
}
resp = card.plainApdu(new ByteString("FF D6 00 09"+lng, HEX).concat(msg));
print("Código SW: " + card.SW.toString(16));
//Escribir en el bloque 0x0A
var msg = new ByteString("1203",ASCII);
var lng = msg.length.toString(HEX);
if(msg.length < 16){
 lng = "0"+msg.length.toString(HEX)
}
resp = card.plainApdu(new ByteString("FF D6 00 0A"+lng, HEX).concat(msg));
print("Código SW: " + card.SW.toString(16));
//Escribir en el bloque 0x0B calcular MAC
var Kaes = new ByteString("0A1A2A3A4A5A6A7A8B9BABBBCBDBEBFB",HEX);
deskey.setComponent(Key.AES, Kaes);

serial = serial.concat(new ByteString("00",HEX));
serial = serial.concat(serial);
var claveTarjeta = crypto.encrypt(deskey,Crypto.AES_ECB,serial);

deskey.setComponent(Key.AES, claveTarjeta);
var Mac = new ByteString("11 SI EE 01 31 VD 01 00 25 20 18 12 12 03",ASCII);
var MacRelleno = Mac.pad(Crypto.ISO9797_METHOD_2, true);
var result = crypto.encrypt(deskey, Crypto.AES_CBC, MacRelleno, claveTarjeta.add(1));
result = result.right(8).left(4);

print("Comparar MACS ------>"+result);
//guardar MAC en OB
resp = card.plainApdu(new ByteString("FF D6 00 0B 04", HEX).concat(result));
print("Código SW: " + card.SW.toString(16));


card.close();