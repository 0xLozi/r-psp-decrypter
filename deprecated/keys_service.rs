use crate::{keys::{G_TAG_INFO, G_TAG_INFO_2}, tag_info::{TAG_INFO, TAG_INFO2}};

pub fn get_tag_info(tagFind: u32) -> Option<&'static TAG_INFO>{

    for itag in &G_TAG_INFO {
        if itag.tag == tagFind {
            return Some(itag);
        }
    }

    return None; // Which means not found
}

pub fn get_tag_info_2(tagFing: u32) -> Option<&'static TAG_INFO2> {
    for itag in &G_TAG_INFO_2 {
        if itag.tag == tagFing {
            return Some(itag);
        }
    }
    None
}