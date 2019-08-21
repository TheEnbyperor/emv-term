extern crate pcsc;

use std::collections::VecDeque;
use std::convert::TryFrom;
use std::ffi::CString;
use std::fmt;

#[derive(Debug)]
struct ApduCommand {
    class: u8,
    instruction: u8,
    param1: u8,
    param2: u8,
    data: Vec<u8>,
    length_expected: u8,
}

struct ApduResponse {
    data: Vec<u8>,
    sw1: u8,
    sw2: u8,
}

impl fmt::Debug for ApduResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApduResponse")
            .field("data", &format_args!("{:02x?}", self.data))
            .field("sw1", &format_args!("{:02x}", self.sw1))
            .field("sw2", &format_args!("{:02x}", self.sw2))
            .finish()
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
enum TagID {
    IssuerIdentificationNumber,
    ApplicationDedicatedFileName,
    ApplicationLabel,
    LanguagePreference,
    IssuerURL,
    InternationalBankAccountNumber,
    BankIdentifierCode,
    IssuerCountryCodeAlpha2,
    IssuerCountryCodeAlpha6,
    ApplicationTemplate,
    FileControlInformationTemplate,
    ReadRecordResponseMessageTemplate,
    DirectoryDiscretionaryTemplate,
    DedicatedFileName,
    ApplicationPriorityIndicator,
    ShortFileIdentifier,
    DirectoryDefinitionFileName,
    ApplicationIdentifier,
    IssuerCodeTableIndex,
    ApplicationPreferredName,
    ProcessingOptionsDataObjectList,
    LogEntry,
    FileControlInformationProprietaryTemplate,
    FileControlInformationIssuerDiscretionaryData,
    Unknown(u32),
}

impl From<u32> for TagID {
    fn from(value: u32) -> Self {
        match value {
            0x42 => TagID::IssuerIdentificationNumber,
            0x4F => TagID::ApplicationDedicatedFileName,
            0x50 => TagID::ApplicationLabel,
            0x5f2d => TagID::LanguagePreference,
            0x5f50 => TagID::IssuerURL,
            0x5f53 => TagID::InternationalBankAccountNumber,
            0x5f54 => TagID::BankIdentifierCode,
            0x5f55 => TagID::IssuerCountryCodeAlpha2,
            0x5f56 => TagID::IssuerCountryCodeAlpha6,
            0x61 => TagID::ApplicationTemplate,
            0x6f => TagID::FileControlInformationTemplate,
            0x70 => TagID::ReadRecordResponseMessageTemplate,
            0x73 => TagID::DirectoryDiscretionaryTemplate,
            0x84 => TagID::DedicatedFileName,
            0x87 => TagID::ApplicationPriorityIndicator,
            0x88 => TagID::ShortFileIdentifier,
            0x9d => TagID::DirectoryDefinitionFileName,
            0x9f06 => TagID::ApplicationIdentifier,
            0x9f11 => TagID::IssuerCodeTableIndex,
            0x9f12 => TagID::ApplicationPreferredName,
            0x9f38 => TagID::ProcessingOptionsDataObjectList,
            0x9f4d => TagID::LogEntry,
            0xa5 => TagID::FileControlInformationProprietaryTemplate,
            0xbf0c => TagID::FileControlInformationIssuerDiscretionaryData,
            u => TagID::Unknown(u)
        }
    }
}

#[derive(Debug, Clone)]
enum TagContents {
    Invalid,
    String(String),
    Bytes(Vec<u8>),
    Byte(u8),
    Constructed(TagList)
}

impl TagContents {
    fn make_primitive(bytes: &[u8], tag: &TagID) -> Self {
        match tag {
            TagID::DedicatedFileName | TagID::LanguagePreference | TagID::ApplicationPreferredName | TagID::ApplicationLabel => {
                match String::from_utf8(bytes.to_vec()) {
                    Ok(s) => TagContents::String(s),
                    Err(_) => TagContents::Invalid,
                }
            }
            TagID::ShortFileIdentifier | TagID::ApplicationPriorityIndicator => TagContents::Byte(bytes[0]),
            _ => TagContents::Bytes(bytes.to_vec())
        }
    }
}

#[derive(Clone)]
struct Tag {
    id: TagID,
    contents: TagContents,
}


impl Tag {
    fn get_tag(&self, tag_id: TagID) -> Option<&Tag> {
        match &self.contents {
            TagContents::Constructed(tl) => tl.get_tag(tag_id),
            _ => None
        }
    }

    fn get_tags(&self, tag_id: TagID) -> Vec<Tag> {
        match &self.contents {
            TagContents::Constructed(tl) => tl.get_tags(tag_id),
            _ => vec![]
        }
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alternate = f.alternate();
        let mut d = f.debug_struct("Tag");
        d.field("id", &format_args!("{:02x?}", self.id));
        if alternate {
            d.field("contents", &format_args!("{:#02x?}", self.contents));
        } else {
            d.field("contents", &format_args!("{:02x?}", self.contents));
        }
        d.finish()
    }
}

#[derive(Debug, Clone)]
struct TagList {
    tags: Vec<Tag>
}

impl TagList {
    fn get_tag(&self, tag_id: TagID) -> Option<&Tag> {
        for tag in &self.tags {
            if tag.id == tag_id {
                return Some(tag)
            }
        }
        None
    }

    fn get_tags(&self, tag_id: TagID) -> Vec<Tag> {
        let mut tags: Vec<Tag> = vec![];
        for tag in &self.tags {
            if tag.id == tag_id {
                tags.push(tag.clone())
            }
        }
        tags
    }
}

impl TagList {
    fn read_byte(vec: &mut VecDeque<u8>) -> Result<u8, pcsc::Error> {
        match vec.pop_front() {
            Some(i) => Ok(i),
            None => Err(pcsc::Error::Eof)
        }
    }

    fn read_id(vec: &mut VecDeque<u8>) -> Result<u32, pcsc::Error> {
        let mut id = Self::read_byte(vec)? as u32;

        if (id & 0b11111) == 0b11111 {
            let next_id = Self::read_byte(vec)?;
            id <<= 8;
            id |= next_id as u32;

            while next_id & 0b10000000 == 0b10000000 {
                let next_id = Self::read_byte(vec)?;
                id <<= 8;
                id |= next_id as u32;
            }
        }

        Ok(id)
    }

    fn is_id_primitive(id: u32) -> bool {
        let mut data = id;
        while (data & 0xffffff00) != 0 {
            data >>= 8;
        }
        data & 0b00100000 != 0b00100000
    }

    fn read_length(vec: &mut VecDeque<u8>) -> Result<u64, pcsc::Error> {
        let mut length = Self::read_byte(vec)? as u64;

        if (length & 0b10000000) == 0b10000000 {
            let num_octets = length & 0b01111111;
            length = 0;
            while num_octets > 0 {
                let octet = Self::read_byte(vec)? as u64;
                length <<= 8;
                length |= octet;
            }
        }

        Ok(length)
    }

    fn read_content(vec: &mut VecDeque<u8>, length: u64) -> Result<Vec<u8>, pcsc::Error> {
        let mut out = vec![];
        while out.len() != length as usize {
            out.push(Self::read_byte(vec)?);
        }
        Ok(out)
    }
}

impl TryFrom<&[u8]> for TagList {
    type Error = pcsc::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let data: VecDeque<u8> = value.to_vec().into();
        TagList::try_from(&data)
    }
}

impl TryFrom<&VecDeque<u8>> for TagList {
    type Error = pcsc::Error;

    fn try_from(value: &VecDeque<u8>) -> Result<Self, Self::Error> {
        let mut data = value.clone();
        let mut out = TagList {
            tags: vec![]
        };

        while data.len() != 0 {
            let id = Self::read_id(&mut data)?;
            let tag_id = TagID::from(id);
            let length = Self::read_length(&mut data)?;
            let contents = Self::read_content(&mut data, length)?;

            if Self::is_id_primitive(id) {
                let contents = TagContents::make_primitive(&contents, &tag_id);
                let tag = Tag {
                    id: tag_id,
                    contents,
                };
                out.tags.push(tag);
            } else {
                let tag_list = TagList::try_from(&VecDeque::from(contents))?;
                let tag = Tag {
                    id: tag_id,
                    contents: TagContents::Constructed(tag_list)
                };
                out.tags.push(tag);
            }
        }

        Ok(out)
    }
}

#[derive(Debug)]
struct ApplicationPriorityIndicator {
    auto_selection_allowed: bool,
    priority: u8,
}

impl From<&Tag> for ApplicationPriorityIndicator {
    fn from(value: &Tag) -> Self {
        let contents = match value.contents {
            TagContents::Byte(b) => b,
            _ => unreachable!()
        };
        let auto_selection_allowed = contents & 0b10000000 == 0;
        let priority = contents & 0b1111;
        Self {
            auto_selection_allowed,
            priority
        }
    }
}

fn send_apdu(card: &pcsc::Card, apdu_command: &ApduCommand) -> Result<ApduResponse, pcsc::Error> {
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

fn find_reader(ctx: &pcsc::Context) -> Result<CString, pcsc::Error> {
    println!("Looking for card, insert one now...");

    let mut readers_buf = [0; 2048];
    let mut reader_states = vec![
        pcsc::ReaderState::new(pcsc::PNP_NOTIFICATION(), pcsc::State::UNAWARE),
    ];
    let mut first_iter = true;

    loop {
        fn is_dead(rs: &pcsc::ReaderState) -> bool {
            rs.event_state().intersects(pcsc::State::UNKNOWN | pcsc::State::IGNORE)
        }
        reader_states.retain(|rs| !is_dead(rs));

        let names = ctx.list_readers(&mut readers_buf)?;
        for name in names {
            if !reader_states.iter().any(|rs| rs.name() == name) {
                reader_states.push(pcsc::ReaderState::new(name, pcsc::State::UNAWARE));
            }
        }

        for rs in &mut reader_states {
            rs.sync_current_state();
        }

        ctx.get_status_change(None, &mut reader_states)?;

        if !first_iter {
            for rs in &reader_states {
                if rs.name() != pcsc::PNP_NOTIFICATION() {
                    if rs.event_state().contains(pcsc::State::CHANGED | pcsc::State::PRESENT) {
                        println!("Found card in reader {:?}", rs.name());
                        return Ok(rs.name().into());
                    }
                }
            }
        }
        first_iter = false;
    }
}

fn card_read_record(card: &pcsc::Card, short_file_identifier: u8, record_number: u8) -> Result<TagList, pcsc::Error> {
    let apdu_cmd = ApduCommand {
        class: 0x00,
        instruction: 0xb2,
        param1: record_number,
        param2: (short_file_identifier & 0b00011111) << 3 | 0b00000100,
        data: vec![],
        length_expected: 0,
    };

    let data = send_apdu(card, &apdu_cmd)?;
    let tag_list = TagList::try_from(data.data.as_slice())?;
    Ok(tag_list)
}

fn card_select(card: &pcsc::Card, file_name: &str, next: bool) -> Result<TagList, pcsc::Error> {
    let mut param2 = 0;
    if next {
        param2 |= 0b10;
    }

    let apdu_cmd = ApduCommand {
        class: 0x00,
        instruction: 0xa4,
        param1: 0b00000100,
        param2,
        data: file_name.to_owned().into_bytes(),
        length_expected: 0,
    };

    let data = send_apdu(card, &apdu_cmd)?;

    let tag_list = TagList::try_from(data.data.as_slice())?;
    Ok(tag_list)
}

fn compare_slice<T: PartialEq>(p1: &[T], p2: &[T]) -> bool {
    if p1.len() != p1.len() {
        return false;
    }
    let mut i = 0;
    for v1 in p1 {
        if &p2[i] != v1 {
            return false;
        }
        i+= 1;
    }
    true
}

fn get_pse_sfi(card: &pcsc::Card) -> Option<u8> {
    let select_resp = match card_select(&card, "1PAY.SYS.DDF01", false) {
        Ok(r) => r,
        Err(_) => return None
    };
    let fci = select_resp.get_tag(TagID::FileControlInformationTemplate)?;
    let fcipt = fci.get_tag(TagID::FileControlInformationProprietaryTemplate)?;
    match fcipt.get_tag(TagID::ShortFileIdentifier)?.contents {
        TagContents::Byte(b) => Some(b),
        _ => unreachable!()
    }
}

fn find_possible_applications(card: &pcsc::Card, sfi: u8) -> Vec<Tag> {
    let acceptable_adf_names = [
        [0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10], // Mastercard
        [0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10] // Visa
    ];
    let mut possible_applications = vec![];

    let mut i = 1;
    loop {
        let record_result = card_read_record(&card, sfi, i);
        match record_result {
            Ok(r) => {
                let record = match r.get_tag(TagID::ReadRecordResponseMessageTemplate) {
                    Some(r) => r,
                    None => continue
                };
                let applications = record.get_tags(TagID::ApplicationTemplate);

                'applications: for application in applications {
                    let adf_name = match &match application.get_tag(TagID::ApplicationDedicatedFileName) {
                        Some(n) => n,
                        None => continue
                    }.contents {
                        TagContents::Bytes(a) => a,
                        _ => unreachable!()
                    };
                    for acceptable_name in &acceptable_adf_names {
                        if compare_slice(acceptable_name, &adf_name) {
                            possible_applications.push(application);
                            continue 'applications;
                        }
                    }
                }
            },
            Err(_) => break
        }
        i += 1;
    }

    possible_applications
}

fn main() {
    let ctx = match pcsc::Context::establish(pcsc::Scope::User) {
        Ok(c) => c,
        Err(e) => {
            println!("Unable to open context: {}", e);
            return;
        }
    };

    let reader = find_reader(&ctx).expect("Unable to find card");
    let card = ctx.connect(&reader, pcsc::ShareMode::Exclusive, pcsc::Protocols::ANY).expect("Unable to connect to card");

    let sfi = get_pse_sfi(&card).expect("Unable to read PSE");
    let possible_applications = find_possible_applications(&card, sfi);

    if possible_applications.len() == 0 {
        panic!("No possible applications found");
    } else if possible_applications.len() == 1 {
        let application = &possible_applications[0];
        let priority = ApplicationPriorityIndicator::from(application.get_tag(TagID::ApplicationPriorityIndicator).expect("No API"));
        println!("{:?}", priority);
    }

    println!("{:?}", possible_applications);
}
