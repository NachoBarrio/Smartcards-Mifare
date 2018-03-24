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

//Leer paginas
var Kaes = new ByteString("0A1A2A3A4A5A6A7A8B9BABBBCBDBEBFB",HEX);
deskey.setComponent(Key.AES, Kaes);

serial = serial.concat(new ByteString("00",HEX));
serial = serial.concat(serial);
var claveTarjeta = crypto.encrypt(deskey,Crypto.AES_ECB,serial);

//leer pagina4
resp = card.sendApdu(0xFF, 0xB0, 0x00, 4, 4);
print("Código SW: " + card.SW.toString(16));
print("Pagina 4: "+resp.toString(ASCII));
if(resp.toString(ASCII) == "00NO"){
	print("Ticket inválido");
}else if(resp.toString(ASCII) == "11SI"){
	resp = card.sendApdu(0xFF, 0xB0, 0x00, 0x0B, 4);
	print("Código SW: " + card.SW.toString(16));
	
	deskey.setComponent(Key.AES, claveTarjeta);
	var Mac = new ByteString("11 SI EE 01 31 VD 01 00 25 20 18 12 12 03",ASCII);
	var MacRelleno = Mac.pad(Crypto.ISO9797_METHOD_2, true);
	var result = crypto.encrypt(deskey, Crypto.AES_CBC, MacRelleno, claveTarjeta.add(1));
	result = result.right(8).left(4);
	print("Comparar Mac generada: "+result+"<------->"+resp);
	if(result.toString() == resp.toString()){
		var cancelacion = new ByteString("00NO",ASCII);
		resp = card.plainApdu(new ByteString("FF D6 00 0B 04", HEX).concat(cancelacion));
	    print("Código SW: " + card.SW.toString(16));
		print("Torno abierto");
	}
}else{
	print("Ticket malformado");
}