/// Scramble the modulus for username/password encryption.
pub fn scramble_modulus(modulus: &mut [u8]) {
    for i in 0..4 {
        modulus.swap(i, i + 77);
    }
    for i in 0..64 {
        modulus[i] ^= modulus[i + 64];
    }
    for i in 0..4 {
        modulus[i + 13] ^= modulus[i + 52];
    }
    for i in 0..64 {
        modulus[i + 64] ^= modulus[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scramble_modulus_success() {
        // Arrange
        let mut modulus = hex::decode("9a277669023723947d0ebdccef967a24c715018df6ce66414fccd0f5bab54124b8caac6d7f52f8bbbab7de926b4f0ac4cc84793196e44928774a57737d0e4ee02962952257506e898846e353fa5fee31409a1d32124fb8df53d969dd7aa222866fa85e106f8a07e333d8ded4b10a8300b32d5f47cc5eab14033fa2bc0950b5c9").
            expect("Fail to decode modulus");

        // Act
        scramble_modulus(&mut modulus);

        // Assert
        assert_eq!(
            hex::encode(modulus),
            "768ca46255674d1df5485e9f1556e7b0928f1cbfe481de9e1c15b928c01763a2d762f27d10d8ff58896f0046da4589c47fa926765abae23c7475f5cf745efb295fee3140023723947d0ebdccefccc0c6fb15018df6ce66414fccd0f5bab54124b8caac6d7f52f8bbbab7de926b4f0ac4cc84793196e44928774a57737d0e4ee0",
        );
    }
}
