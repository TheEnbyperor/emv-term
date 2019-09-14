#[derive(Debug)]
pub struct ApduCommand {
    class: u8,
    instruction: u8,
    param1: u8,
    param2: u8,
    data: Vec<u8>,
    length_expected: u8,
}

impl ApduCommand {
    pub fn new(class: u8, instruction: u8, param1: u8, param2: u8, data: &[u8], length_expected: u8) -> Self {
        Self {
            class,
            instruction,
            param1,
            param2,
            data: data.to_vec(),
            length_expected
        }
    }
}

pub struct ApduResponse {
    data: Vec<u8>,
    sw1: u8,
    sw2: u8,
}

impl ApduResponse {
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn status(&self) -> (&u8, &u8) {
        (&self.sw1, &self.sw2)
    }
}

impl std::fmt::Debug for ApduResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApduResponse")
            .field("data", &format_args!("{:02x?}", self.data))
            .field("sw1", &format_args!("{:02x}", self.sw1))
            .field("sw2", &format_args!("{:02x}", self.sw2))
            .finish()
    }
}

pub fn send_apdu(card: &pcsc::Card, apdu_command: &ApduCommand) -> Result<ApduResponse, pcsc::Error> {
    let mut apdu_out = vec![apdu_command.class, apdu_command.instruction, apdu_command.param1, apdu_command.param2];

    if apdu_command.data.len() > 0 {
        apdu_out.push(apdu_command.data.len() as u8);
        apdu_out.extend(&apdu_command.data);
    }

    apdu_out.push(apdu_command.length_expected);

    let len_expected = if apdu_command.length_expected == 0 {
        256
    } else {
        apdu_command.length_expected as usize
    };

    let mut apdu_in = vec![0; len_expected + 2];
    let data = card.transmit(&apdu_out, &mut apdu_in)?;

    let response_len = data.len();
    let mut response = ApduResponse {
        data: data[0..response_len - 2].to_vec(),
        sw1: data[response_len - 2],
        sw2: data[response_len - 1],
    };

    while response.sw1 == 0x61 {
        let new_apdu_command = ApduCommand {
            class: apdu_command.class,
            instruction: 0xC0,
            param1: 0x00,
            param2: 0x00,
            data: vec![],
            length_expected: response.sw2,
        };

        let new_response = send_apdu(card, &new_apdu_command)?;
        response.sw1 = new_response.sw1;
        response.sw2 = new_response.sw2;
        response.data.extend(new_response.data)
    }

    if response.sw1 == 0x6c {
        let new_apdu_command = ApduCommand {
            class: apdu_command.class,
            instruction: apdu_command.instruction,
            param1: apdu_command.param1,
            param2: apdu_command.param2,
            data: apdu_command.data.to_vec(),
            length_expected: response.sw2,
        };

        return send_apdu(card, &new_apdu_command);
    }

    match (response.sw1, response.sw2) {
        (0x90, 0x00) => Ok(response),
        (0x6A, 0x81) => Err(pcsc::Error::UnsupportedFeature),
        (0x6A, 0x82) | (0x6A, 0x83) => Err(pcsc::Error::FileNotFound),
        _ => Err(pcsc::Error::UnknownError)
    }
}