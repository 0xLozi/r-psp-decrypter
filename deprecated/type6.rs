
struct PrxType6 {
    data: [u8;0x150],
}

impl PrxType6 {
    fn new(prx: &[u8]) -> Self {
        let mut data = [0u8; 0x150];
        
        // tag
        data[0..0x04].copy_from_slice(&prx[0xD0..0xD4]);
        
        // empty (0x38 bytes de ceros)
        // Ya se encuentran llenos gracias a que inicié el arreglo con todos ceros...

        // C++: memcpy(ecdsaSignatureTail, prx+0x10C, sizeof(ecdsaSignatureTail));
        data[0x3C..0x5C].copy_from_slice(&prx[0x10C..0x12C]);

        // 4. id (0x5C, igual que en el Tipo 5 y Tipo 2)
        data[0x5C..0x6C].copy_from_slice(&prx[0x140..0x150]);
        
        // 5. sha1
        // u8 sha1[0x14];
        data[0x6C..0x80].copy_from_slice(&prx[0x12C..0x140]);
        
        // kirkHeader (Según el código se encuentra partido en dos: "kirk header is split between 0x80->0xB0 and 0xC0->0xD0")
        data[0x80..0xB0].copy_from_slice(&prx[0x80..0xB0]);
        data[0xB0..0xC0].copy_from_slice(&prx[0xC0..0xD0]);
        
        // kirkMetadata
        data[0xC0..0xD0].copy_from_slice(&prx[0xB0..0xC0]);
        
        // prxHeader
        data[0xD0..0x150].copy_from_slice(&prx[0..0x80]);

        Self { data }
    }


    // GETTERRRRRRRRRRRRRRRRRRS
    fn tag(&self) -> &[u8] {
        &self.data[0..0x04]
    }

    // getter del nuevo campo
    fn ecdsa_signature_tail(&self) -> &[u8] {
        &self.data[0x3C..0x5C]
    }

    fn id(&self) -> &[u8] {
        &self.data[0x5C..0x6C]
    }

    fn sha1(&self) -> &[u8] {
        &self.data[0x6C..0x80]
    }

    fn kirk_header(&self) -> &[u8] {
        &self.data[0x80..0xC0]
    }

    fn prx_header(&self) -> &[u8] {
        &self.data[0xD0..0x150]
    }   

    // DECRYPT
    fn decrypt_header(&mut self, key_id: i32) -> Result<(), KirkError> {
        // kirk7(id, id, 0x60, key);
        let inicio = 0x5C;
        let fin = inicio + 0x60;
        
        kirk7(&mut self.data[inicio..fin], key_id)?;
        
        Ok(())
    }
}
