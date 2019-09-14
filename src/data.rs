use std::convert::TryFrom;

#[derive(Debug)]
pub struct ApplicationPriorityIndicator {
    auto_selection_allowed: bool,
    priority: u8,
}

impl ApplicationPriorityIndicator {
    pub fn auto_selection_allowed(&self) -> bool {
        self.auto_selection_allowed
    }

    pub fn prority(&self) -> u8 {
        self.priority
    }
}

impl TryFrom<&crate::tlv::Tag> for ApplicationPriorityIndicator {
    type Error = &'static str;

    fn try_from(value: &crate::tlv::Tag) -> Result<Self, Self::Error> {
        let contents = match value.contents() {
            crate::tlv::TagContents::Byte(b) => b,
            _ => return Err("Not a byte value")
        };
        let auto_selection_allowed = contents & 0b10000000 == 0;
        let priority = contents & 0b1111;
        Ok(Self {
            auto_selection_allowed,
            priority,
        })
    }
}

pub struct Application {
    name: String,
    adf_name: Vec<u8>,
    priority: ApplicationPriorityIndicator,
}

impl Application {
    fn get_application_name(tag: &crate::tlv::Tag) -> Option<String> {
        match match (tag.get_tag(crate::tlv::TagID::ApplicationPreferredName), tag.get_tag(crate::tlv::TagID::IssuerCodeTableIndex)) {
            (Some(n), Some(i)) => match &n.contents() {
                crate::tlv::TagContents::Bytes(b) => match &i.contents() {
                    crate::tlv::TagContents::Byte(i) => crate::util::code_table_index_decode(b, *i),
                    _ => unreachable!()
                },
                _ => unreachable!()
            },
            (_, _) => None
        } {
            Some(s) => Some(s.to_string()),
            None => {
                match tag.get_tag(crate::tlv::TagID::ApplicationLabel) {
                    Some(n) => match &n.contents() {
                        crate::tlv::TagContents::String(s) => Some(s.to_string()),
                        crate::tlv::TagContents::Invalid => None,
                        _ => unreachable!()
                    },
                    None => None
                }
            }
        }
    }

    pub fn priority(&self) -> &ApplicationPriorityIndicator {
        &self.priority
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn aid(&self) -> &[u8] {
        &self.adf_name
    }
}

impl TryFrom<&crate::tlv::Tag> for Application {
    type Error = &'static str;

    fn try_from(value: &crate::tlv::Tag) -> Result<Self, Self::Error> {
        let name = match Application::get_application_name(value) {
            Some(s) => s,
            None => return Err("No application name")
        };
        let api = ApplicationPriorityIndicator::try_from(match value.get_tag(crate::tlv::TagID::ApplicationPriorityIndicator) {
            Some(p) => p,
            None => return Err("No API")
        })?;
        let adf = match match value.get_tag(crate::tlv::TagID::ApplicationDedicatedFileName) {
            Some(a) => a,
            None => return Err("No ADF name")
        }.contents() {
            crate:: tlv::TagContents::Bytes(b) => b,
            _ => unreachable!()
        };

        Ok(Self {
            name,
            adf_name: adf.to_owned(),
            priority: api,
        })
    }
}