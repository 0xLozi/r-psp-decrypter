use crate::{keys::G_TAG_INFO, tag_info::TAG_INFO};

pub fn get_tag_info(tagFind: u32) -> Option<&'static TAG_INFO>{

    for itag in &G_TAG_INFO {
        if (itag.tag == tagFind) {
            return Some(itag);
        }
    }

    return None; // Which means not found
}