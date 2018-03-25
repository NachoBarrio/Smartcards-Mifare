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

// ------ CERRDURA ---------------
var habitacionEjemplo = "UNOC";
// LEer pagina4
resp = card.sendApdu(0xFF, 0xB0, 0x00, 4, 4);
print("Código SW: " + card.SW.toString(16));
print("Pagina 4: "+resp.toString(ASCII));
if(resp.toString(ASCII) == "TODO"){
	print("Se abre la puerta con llave maestra");
}else{
   var diamesSalida = card.sendApdu(0xFF, 0xB0, 0x00, 9, 4);
   var anioSalida = card.sendApdu(0xFF, 0xB0, 0x00, 10, 4);
   print("crear fecha: "+anioSalida.toString(ASCII)+","+diamesSalida.bytes(2,2).toString(ASCII)+","+diamesSalida.bytes(0,2).toString(ASCII));
   var fechaSalida = new Date(anioSalida.toString(ASCII),diamesSalida.bytes(2,2).toString(ASCII), diamesSalida.bytes(0,2).toString(ASCII));
   print("FechaSalida: "+fechaSalida.toString());
   print("Ahora: "+new Date().toString());
   if(habitacionEjemplo == resp.toString(ASCII) && (fechaSalida >= Date.now())){
   		print("Se abre la puerta exacta");
   }else{
   	print("No se abre la puerta exacta");
   }
}

