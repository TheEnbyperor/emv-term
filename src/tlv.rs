use std::collections::VecDeque;
use std::convert::TryFrom;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum TagID {
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
    CommandTemplate,
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

impl From<TagID> for u32 {
    fn from(value: TagID) -> Self {
        match value {
            TagID::CommandTemplate => 0x83,
            TagID::Unknown(u) => u,
            _ => unimplemented!()
        }
    }
}

fn int_to_least_bytes(value: u64) -> Vec<u8> {
    let mut bytes = VecDeque::from(value.to_be_bytes().to_vec());
    while bytes[0] == 0 && bytes.len() > 1 {
        bytes.pop_front();
    }
    bytes.into()
}

impl From<TagID> for Vec<u8> {
    fn from(value: TagID) -> Self {
        int_to_least_bytes(u32::from(value) as u64)
    }
}

#[derive(Debug, Clone)]
pub enum TagContents {
    Invalid,
    String(String),
    Bytes(Vec<u8>),
    Byte(u8),
    Number(u32),
    Constructed(TagList),
}

impl TagContents {
    fn make_primitive(bytes: &[u8], tag: &TagID) -> Self {
        match tag {
            TagID::LanguagePreference | TagID::ApplicationLabel => {
                match String::from_utf8(bytes.to_vec()) {
                    Ok(s) => TagContents::String(s),
                    Err(_) => TagContents::Invalid,
                }
            }
            TagID::ShortFileIdentifier | TagID::ApplicationPriorityIndicator | TagID::IssuerCodeTableIndex => TagContents::Byte(bytes[0]),
            _ => TagContents::Bytes(bytes.to_vec())
        }
    }
}

impl From<&TagContents> for Vec<u8> {
    fn from(value: &TagContents) -> Self {
        match value {
            TagContents::Invalid => vec![],
            TagContents::String(s) => s.to_owned().into_bytes(),
            TagContents::Bytes(b) => b.to_owned(),
            TagContents::Byte(b) => vec![*b],
            TagContents::Number(n) => n.to_be_bytes().to_vec(),
            TagContents::Constructed(t) => t.into()
        }
    }
}

#[derive(Clone)]
pub struct Tag {
    id: TagID,
    contents: TagContents,
}


impl Tag {
    pub fn new(id: TagID, contents: TagContents) -> Self {
        Self {
            id,
            contents,
        }
    }

    pub fn get_tag(&self, tag_id: TagID) -> Option<&Tag> {
        match &self.contents {
            TagContents::Constructed(tl) => tl.get_tag(tag_id),
            _ => None
        }
    }

    pub fn get_tags(&self, tag_id: TagID) -> Vec<&Tag> {
        match &self.contents {
            TagContents::Constructed(tl) => tl.get_tags(tag_id),
            _ => vec![]
        }
    }

    pub fn contents(&self) -> &TagContents {
        &self.contents
    }
}

impl std::fmt::Debug for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
pub struct TagList {
    tags: Vec<Tag>
}

impl TagList {
    pub fn new() -> Self {
        Self {
            tags: vec![]
        }
    }

    pub fn add_tag(&mut self, tag: Tag){
        self.tags.push(tag);
    }

    pub fn get_tag(&self, tag_id: TagID) -> Option<&Tag> {
        for tag in &self.tags {
            if tag.id == tag_id {
                return Some(tag);
            }
        }
        None
    }

    pub fn get_tags(&self, tag_id: TagID) -> Vec<&Tag> {
        let mut tags: Vec<&Tag> = vec![];
        for tag in &self.tags {
            if tag.id == tag_id {
                tags.push(tag)
            }
        }
        tags
    }

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

    fn make_length(len: u64) -> Vec<u8> {
        let mut out = vec![];

        if len <= 0b01111111 {
            out.push(len as u8);
        } else {
            let bytes = int_to_least_bytes(len);
            let num_octets = bytes.len() as u8 & 0b01111111;
            out.push(num_octets);
            for b in &bytes {
                out.push(*b);
            }
        }
        out
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
        TagList::try_from(&VecDeque::<u8>::from(value.to_vec()))
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
                    contents: TagContents::Constructed(tag_list),
                };
                out.tags.push(tag);
            }
        }

        Ok(out)
    }
}

impl From<&TagList> for Vec<u8> {
    fn from(value: &TagList) -> Self {
        let mut out = vec![];

        for tag in &value.tags {
            let data = Vec::<u8>::from(tag.contents());
            let len = TagList::make_length(data.len() as u64);
            out.extend(Vec::<u8>::from(tag.id));
            out.extend(len);
            out.extend(data);
        }

        out
    }
}

#[derive(Clone)]
pub struct DOLTag {
    id: TagID,
    contents: TagContents,
    exp_len: u8,
}

impl std::fmt::Debug for DOLTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let alternate = f.alternate();
        let mut d = f.debug_struct("DOLTag");
        d.field("id", &format_args!("{:02x?}", self.id));
        if alternate {
            d.field("contents", &format_args!("{:#02x?}", self.contents));
        } else {
            d.field("contents", &format_args!("{:02x?}", self.contents));
        }
        d.field("exp_len", &format_args!("{:?}", self.exp_len));
        d.finish()
    }
}

#[derive(Debug, Clone)]
pub struct DOL {
    fields: Vec<DOLTag>
}

impl DOL {
    pub fn new() -> Self {
        Self {
            fields: vec![]
        }
    }

    fn fit_bytes(value: &[u8], exp_len: u8, numeric: bool) -> Vec<u8> {
        let exp_len = exp_len as usize;
        let mut data = value.to_vec();
        let len = data.len();
        if len == exp_len {
            data
        } else if len < exp_len {
            if !numeric {
                data.extend(vec![0; exp_len - len]);
                data
            } else {
                let mut new_data = vec![0; exp_len - len];
                new_data.extend(data);
                new_data
            }
        } else {
            if !numeric {
                data.split_off(exp_len);
                data
            } else {
                data.split_off(exp_len)
            }
        }
    }
}

impl TryFrom<&[u8]> for DOL {
    type Error = pcsc::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        DOL::try_from(&VecDeque::<u8>::from(value.to_vec()))
    }
}

impl TryFrom<&VecDeque<u8>> for DOL {
    type Error = pcsc::Error;

    fn try_from(value: &VecDeque<u8>) -> Result<Self, Self::Error> {
        let mut data = value.clone();
        let mut out = DOL {
            fields: vec![]
        };

        while data.len() != 0 {
            let id = TagList::read_id(&mut data)?;
            let tag_id = TagID::from(id);
            let length = TagList::read_byte(&mut data)?;

            if TagList::is_id_primitive(id) {
                let tag = DOLTag {
                    id: tag_id,
                    contents: TagContents::Invalid,
                    exp_len: length,
                };
                out.fields.push(tag);
            }
        }

        Ok(out)
    }
}

impl From<DOL> for Vec<u8> {
    fn from(value: DOL) -> Self {
        let mut out = vec![];

        for tag in &value.fields {
            out.extend(match &tag.contents {
                TagContents::Invalid | TagContents::Constructed(_) => vec![0; tag.exp_len as usize],
                TagContents::String(s) => DOL::fit_bytes(&s.to_owned().into_bytes(), tag.exp_len, false),
                TagContents::Bytes(b) => DOL::fit_bytes(&b, tag.exp_len, false),
                TagContents::Byte(b) => DOL::fit_bytes(&[*b], tag.exp_len, false),
                TagContents::Number(n) => DOL::fit_bytes(&n.to_be_bytes(), tag.exp_len, false),
            })
        }

        out
    }
}