use std::convert::TryFrom;

pub fn find_reader(ctx: &pcsc::Context) -> Result<std::ffi::CString, pcsc::Error> {
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

pub fn card_read_record(card: &pcsc::Card, short_file_identifier: u8, record_number: u8) -> Result<crate::tlv::TagList, pcsc::Error> {
    let apdu_cmd = crate::apdu::ApduCommand::new(0x00,0xb2,record_number, (short_file_identifier & 0b00011111) << 3 | 0b00000100, &[], 0);

    let data = crate::apdu::send_apdu(card, &apdu_cmd)?;
    let tag_list = crate::tlv::TagList::try_from(data.data())?;
    Ok(tag_list)
}

pub fn card_select(card: &pcsc::Card, file_name: &[u8], next: bool) -> Result<crate::tlv::TagList, pcsc::Error> {
    let mut param2 = 0;
    if next {
        param2 |= 0b10;
    }

    let apdu_cmd = crate::apdu::ApduCommand::new( 0x00, 0xa4,0b00000100, param2,file_name, 0);

    let data = crate::apdu::send_apdu(card, &apdu_cmd)?;

    let tag_list = crate::tlv::TagList::try_from(data.data())?;
    Ok(tag_list)
}

pub fn card_get_processing_options(card: &pcsc::Card, pdol: &[u8]) -> Result<crate::tlv::TagList, pcsc::Error> {
    let apdu_cmd = crate::apdu::ApduCommand::new( 0x80, 0xa8,0x00, 0x00,pdol, 0);

    let data = crate::apdu::send_apdu(card, &apdu_cmd)?;

    let tag_list = crate::tlv::TagList::try_from(data.data())?;
    Ok(tag_list)
}