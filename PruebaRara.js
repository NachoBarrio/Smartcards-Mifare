card = new Card();
atr = card.reset(Card.RESET_COLD);

crypto = new Crypto();
deskey = new Key();

//-----------------------------------------------------------------------------
readBinaryBlockApdu = new ByteString("FF B0 00", HEX);
function readBinaryBlock(blockNumberHex, numberOfBytesHex) {
  apdu = readBinaryBlockApdu.concat(new ByteString(blockNumberHex, HEX))
                              .concat(new ByteString(numberOfBytesHex, HEX));
  resp = card.plainApdu(apdu);
  print ("x-x-x-x-x-x" + resp);
  print(card.SW.toString(16))
  assert(card.SW.toString(16) == "9000")
  return resp;
}

updateBinaryBlockApdu = new ByteString("FF D6 00", HEX);
function updateBinaryBlock(blockNumberHex, numberOfBytesHex, dataByteString) {
  apdu = updateBinaryBlockApdu.concat(new ByteString(blockNumberHex, HEX))
                              .concat(new ByteString(numberOfBytesHex, HEX))
                              .concat(dataByteString); //paddNext16(dataByteString)
  resp = card.plainApdu(apdu);
  assert(card.SW.toString(16) == "9000")
}
//-----------------------------------------------------------------------------

validity = readBinaryBlock("04", "04");
if (validity.toString(ASCII) == "00NO") {
  print ("Card Not Valid");
}
if (validity.toString(ASCII) == "11SI") {

  MAC = readBinaryBlock("0B", "04");

  masterKey = new ByteString("0A 1A 2A 3A 4A 5A 6A 7A 8B 9B AB BB CB DB EB FB",HEX);
  deskey.setComponent(Key.AES, masterKey);

  cardSerialNumber = card.plainApdu(new ByteString("FF CA 00 00 00", HEX)).concat(new ByteString("00", HEX));

  token = cardSerialNumber.concat(cardSerialNumber);
  deskey.setComponent(Key.AES, masterKey);
  cardEncryptionKey = crypto.encrypt(deskey, Crypto.AES_ECB, token); 

  data = readBinaryBlock("04", "04")
         .concat(readBinaryBlock("05", "04"))
         .concat(readBinaryBlock("06", "04"))
         .concat(readBinaryBlock("07", "04"))
         .concat(readBinaryBlock("08", "04"))
         .concat(readBinaryBlock("09", "04"))
         .concat(readBinaryBlock("0A", "04"));

  data = data.pad(Crypto.ISO9797_METHOD_2, true)
  print ("data: " + data.toString())

  deskey.setComponent(Key.AES, cardEncryptionKey);
  macVerifier = crypto.encrypt(deskey, Crypto.AES_CBC, data, cardEncryptionKey.add(1));

  print (macVerifier)

  macVerifier = macVerifier.right(8).left(4)
  MAC = readBinaryBlock("0B", "04");

  print (macVerifier)
  print (MAC)
  
  assert(macVerifier.equals(MAC))

  invalid = new ByteString("00NO", ASCII);
  data = invalid.concat(data.bytes(4))
  MAC = crypto.encrypt(deskey, Crypto.AES_CBC, data, cardEncryptionKey.add(1)).right(8).left(4);

  updateBinaryBlock("04", "04", invalid);
  updateBinaryBlock("0B", "04", MAC);
  
  print("Ticket used");
  
}

print ("Done");