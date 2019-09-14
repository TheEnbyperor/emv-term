extern crate pcsc;
extern crate encoding;

mod tlv;
mod apdu;
mod util;
mod card;
mod data;

use std::collections::{VecDeque, HashMap};
use std::convert::TryFrom;
use std::ffi::CString;
use std::fmt;


fn get_pse_sfi(card: &pcsc::Card) -> Option<u8> {
    let select_resp = match card::card_select(&card, &"1PAY.SYS.DDF01".to_string().into_bytes(), false) {
        Ok(r) => r,
        Err(_) => return None
    };
    let fci = select_resp.get_tag(tlv::TagID::FileControlInformationTemplate)?;
    let fcipt = fci.get_tag(tlv::TagID::FileControlInformationProprietaryTemplate)?;
    match fcipt.get_tag(tlv::TagID::ShortFileIdentifier)?.contents() {
        tlv::TagContents::Byte(b) => Some(*b),
        _ => unreachable!()
    }
}


fn select_aid(card: &pcsc::Card, aid: &[u8]) -> Option<(Vec<u8>, tlv::Tag)> {
    let select_resp = match card::card_select(&card, aid, false) {
        Ok(r) => r,
        Err(_) => return None
    };
    let fci = select_resp.get_tag(tlv::TagID::FileControlInformationTemplate)?;
    let fcipt = fci.get_tag(tlv::TagID::FileControlInformationProprietaryTemplate)?;
    let df_name = match fci.get_tag(tlv::TagID::DedicatedFileName)?.contents() {
        tlv::TagContents::Bytes(b) => b,
        _ => unreachable!()
    };
    Some((df_name.to_owned(), fcipt.to_owned()))
}

fn find_possible_applications(card: &pcsc::Card, sfi: u8) -> Vec<tlv::Tag> {
    let acceptable_adf_names = [
        [0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10], // Mastercard
        [0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10] // Visa
    ];
    let mut possible_applications = vec![];

    let mut i = 1;
    loop {
        let record_result = card::card_read_record(&card, sfi, i);
        match record_result {
            Ok(r) => {
                let record = match r.get_tag(tlv::TagID::ReadRecordResponseMessageTemplate) {
                    Some(r) => r,
                    None => continue
                };
                let applications = record.get_tags(tlv::TagID::ApplicationTemplate);

                'applications: for application in applications {
                    let adf_name = match &match application.get_tag(tlv::TagID::ApplicationDedicatedFileName) {
                        Some(n) => n,
                        None => continue
                    }.contents() {
                        tlv::TagContents::Bytes(a) => a,
                        _ => unreachable!()
                    };
                    for acceptable_name in &acceptable_adf_names {
                        if util::compare_slice(acceptable_name, &adf_name) {
                            possible_applications.push(application.to_owned());
                            continue 'applications;
                        }
                    }
                }
            }
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

    let reader = card::find_reader(&ctx).expect("Unable to find card");
    let card = ctx.connect(&reader, pcsc::ShareMode::Exclusive, pcsc::Protocols::ANY).expect("Unable to connect to card");

    let sfi = get_pse_sfi(&card).expect("Unable to read PSE");
    let possible_applications = find_possible_applications(&card, sfi);

    let application = if possible_applications.len() == 0 {
        println!("No possible applications found");
        return;
    } else if possible_applications.len() == 1 {
        let application = data::Application::try_from(&possible_applications[0]).expect("Invalid application");
        if !application.priority().auto_selection_allowed() {
            let selected = util::get_input_bool(&format!("Select application {}?", application.name()));
            if !selected {
                return;
            }
        }

        application
    } else {
        unimplemented!();
    };

    println!("Using application: {}", application.name());
    let (df_name, fcipt) = select_aid(&card, &application.aid()).expect("Unable to select application");
    let pdol = match fcipt.get_tag(tlv::TagID::ProcessingOptionsDataObjectList) {
        Some(d) => match &d.contents() {
            tlv::TagContents::Bytes(b) => tlv::DOL::try_from(b.as_slice()).expect("Invalid PDOL"),
            _ => unreachable!()
        },
        None => tlv::DOL::new()
    };

    let pdol_bytes: Vec<u8> = pdol.clone().into();
    let mut pdol_tlv = tlv::TagList::new();
    let pdol_tag = tlv::Tag::new(tlv::TagID::CommandTemplate,  tlv::TagContents::Bytes(pdol_bytes));
    pdol_tlv.add_tag(pdol_tag);

    println!("{:02x?}", Vec::<u8>::from(&pdol_tlv));
    println!("{:02x?}", card::card_get_processing_options(&card, &Vec::<u8>::from(&pdol_tlv)));
}
