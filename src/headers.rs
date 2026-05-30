
// static std::array<u8, 0x90> expandSeed(const u8 *seed, int key, const u8 *bonusSeed = nullptr)
// {
// 	std::array<u8, 0x90> expandedSeed;
// 	// perform some AES-CTR like encryption of seed
// 	for (auto i = 0u; i < expandedSeed.size(); i += 0x10)
// 	{
// 		memcpy(expandedSeed.data()+i, seed, 0x10);
// 		expandedSeed[i] = i/0x10;
// 	}
// 	kirk7(expandedSeed.data(), expandedSeed.data(), expandedSeed.size(), key);
// 	if (bonusSeed)
// 	{
// 		for (auto i = 0u; i < expandedSeed.size(); ++i)
// 		{
// 			expandedSeed[i] ^= bonusSeed[i % 0x10];
// 		}
// 	}
// 	return expandedSeed;
// }

// 144 bytes just to make it clear
pub fn expanded_seed(seed: &u8, key: u32, bonus_seed: u8 ) -> [u8; 0x90] {
    




    [0; 0x90]
}




#[derive(Debug)]
pub struct PrxType0 {
    tag: u32, 
}


impl PrxType0 {
    pub fn recortar() {
        println!("prueba")
    }
}


