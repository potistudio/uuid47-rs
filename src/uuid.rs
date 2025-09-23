#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Uuid128 {
	pub b: [u8; 16],
}

impl Uuid128 {
	pub fn new() -> Self {
		Self { b: [0u8; 16] }
	}

	pub fn uuid_version(&self) -> u8 {
		(&self.b[6] >> 4) & 0x0F
	}

	pub fn set_version(&mut self, ver: u8) {
		self.b[6] = (self.b[6] & 0x0F) | ((ver & 0x0F) << 4);
	}

	pub fn set_variant_rfc4122(&mut self) {
		// 10xxxxxx
		self.b[8] = (self.b[8] & 0x3F) | 0x80;
	}
}
