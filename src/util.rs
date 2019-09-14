use encoding::Encoding;

pub fn compare_slice<T: PartialEq>(p1: &[T], p2: &[T]) -> bool {
    if p1.len() != p1.len() {
        return false;
    }
    let mut i = 0;
    for v1 in p1 {
        if &p2[i] != v1 {
            return false;
        }
        i += 1;
    }
    true
}

pub fn get_input<T: std::str::FromStr>(question: &str) -> T {
    loop {
        print!("{}", question);
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).expect("Unable to read input");
        match input.parse::<T>() {
            Ok(v) => return v,
            Err(_) => continue
        }
    }
}

pub fn get_input_bool(question: &str) -> bool {
    loop {
        print!("{} [Y/N]", question);
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).expect("Unable to read input");
        match input.to_lowercase().as_str() {
            "y" => return true,
            "n" => return false,
            _ => continue
        }
    }
}


pub fn code_table_index_decode(data: &[u8], index: u8) -> Option<String> {
    let encoder = match index {
        1 => encoding::all::ISO_8859_1,
        2 => encoding::all::ISO_8859_2,
        3 => encoding::all::ISO_8859_3,
        4 => encoding::all::ISO_8859_4,
        5 => encoding::all::ISO_8859_5,
        6 => encoding::all::ISO_8859_6,
        7 => encoding::all::ISO_8859_7,
        8 => encoding::all::ISO_8859_8,
        10 => encoding::all::ISO_8859_10,
        13 => encoding::all::ISO_8859_13,
        14 => encoding::all::ISO_8859_14,
        15 => encoding::all::ISO_8859_15,
        16 => encoding::all::ISO_8859_16,
        _ => return None
    };
    match encoder.decode(data, encoding::DecoderTrap::Ignore) {
        Ok(s) => Some(s),
        Err(_) => None
    }
}