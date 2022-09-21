// The Vigenère Cipher encrypts a plain text file by performing
// a rotation of each character in the plain.  The rotation depends
// on the key, and every character in the key rotates the corresponding
// plain text value by that amount.  If the key is shorter than the
// plain text, then key is cycled.

// subtract 65 to convert to the alphabetic position (A = 0, B = 1.. )
fn to_alpha_index(c: &char) -> u8 {
    (*c as u8) - 65
}

// convert alphabetic position to a char
fn to_char(i: u8) -> char {
    (i + 65) as char
}

// takes a numeric value that represents a plain text letter  and an amount to rotate
// if index = 90 which is Z and amt = 1, than 65 which is A should
// be returned (wraps)
fn rotate_index(i: u8, amt: u8) -> u8 {
    (i + amt) % 26
}

// Used by decrypt to undo rotate_index()
fn reverse_rotate_index(i: u8, amt: u8) -> u8 {
    let a = (i as i32 - amt as i32) as f32;
    let n = 26 as f32;

    // This is the definition of modulo given by Donald Knuth.
    // I use this definition instead of the builtin mod % operator
    // because I want the result to be positive.
    // https://torstencurdt.com/tech/posts/modulo-of-negative-numbers
    (a - n * (a / n).floor()) as u8
}

fn enc(key: String, val: String) -> String {
    let key_vec = key.chars().collect::<Vec<char>>();
    let key_length = key_vec.len();

    // Create an array where each letter is converted to
    // it's numeric position: [A, B, C] becomes [0, 1, 2].
    let alpha_index = val.chars().map(|c| to_alpha_index(&c));

    // Allocate some space to return the value on the stack.
    let mut return_val = String::from("");

    // Iterate over the numeric positions and perform the rotation.
    for (i, a_i) in alpha_index.enumerate() {
        // Cycle over the key and mod by the length
        // if a key for example is half the size of the plain text
        // then each key value will be used twice.
        let key_char: char = key_vec[i % key_length];

        // Find the amount to shift by given a key char.
        let shift_amt: u8 = to_alpha_index(&key_char);

        // Apply the rotation.
        let index = rotate_index(a_i, shift_amt);

        // Convert back to a char.
        let enc_char = to_char(index);

        return_val.push(enc_char);
    }
    return_val
}

fn dec(key: String, val: String) -> String {
    let key_vec = key.chars().collect::<Vec<char>>();
    let key_length = key_vec.len();
    let alpha_index = val.chars().map(|c| to_alpha_index(&c));

    let mut return_val = String::from("");
    for (i, a_i) in alpha_index.enumerate() {
        let key_char: char = key_vec[i % key_length];
        let shift_amt: u8 = to_alpha_index(&key_char);

        let index = reverse_rotate_index(a_i, shift_amt);
        let enc_char = to_char(index);

        return_val.push(enc_char);
    }

    return_val
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_alpha_pos() {
        assert_eq!(0, to_alpha_index(&'A'));
    }

    #[test]
    fn test_to_char() {
        assert_eq!('A', to_char(0));
    }

    #[test]
    fn test_rotate_index() {
        assert_eq!(0, rotate_index(25, 1));
    }

    #[test]
    fn test_enc() {
        let cipher_key = String::from("DUH");
        let plain_text = String::from("CRYPTO");
        assert_eq!("FLFSNV", enc(cipher_key, plain_text));

        let cipher_key = String::from("DUH");
        let plain_text = String::from("THEYDRINKTHETEA");
        assert_eq!("WBLBXYLHRWBLWYH", enc(cipher_key, plain_text));
    }

    #[test]
    fn test_dec() {
        let cipher_key = String::from("DUH");
        let plain_text = String::from("FLFSNV");
        assert_eq!("CRYPTO", dec(cipher_key, plain_text));

        let cipher_key = String::from("DUH");
        let plain_text = String::from("WBLBXYLHRWBLWYH");
        assert_eq!("THEYDRINKTHETEA", dec(cipher_key, plain_text));
    }
}
