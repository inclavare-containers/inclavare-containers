use std::collections::HashMap;
use crate::tdx::binaryblob;
use crate::tdx::tdeventlog;
use crate::tdx::rtmr;
use sha2::{Sha384, Digest};
use anyhow::Result;

pub struct TDEventLogActor {
    _data: Vec<u8>,
    _log_base: u64,
    _log_length: usize,
    _specid_header: tdeventlog::TDEventLogSpecIdHeader,
    _event_logs: Vec<tdeventlog::TDEventLogEntry>,
    _rtmrs: HashMap<usize, rtmr::RTMR>,
}

impl TDEventLogActor {
    pub fn new(base: u64, length: usize, tdel_data: Vec<u8>) -> Self {
        let mut actor = Self {
            _data: tdel_data,
            _log_base: base,
            _log_length: length,
            _specid_header: tdeventlog::TDEventLogSpecIdHeader::new(base),
            _event_logs: vec![],
            _rtmrs: HashMap::new(),
        };
        match actor.process() {
            Ok(_) => debug!("process event OK"),
            Err(e) => error!("process event failed: {}", e.to_string())
        }
        actor
    }

    fn _replay_single_rtmr(event_logs: &Vec<tdeventlog::TDEventLogEntry>) -> rtmr::RTMR {
        let mut rtmr = [0; rtmr::RTMR_LENGTH_BY_BYTES];

        for event_log in event_logs.iter() {
            let digest = &event_log._digests[0];
            let mut sha384_algo = Sha384::new();
            sha384_algo.update(&rtmr);
            sha384_algo.update(digest.as_slice());
            rtmr.copy_from_slice(sha384_algo.finalize().as_slice());
        }

        rtmr::RTMR::new(rtmr.to_vec())
    }
    
    fn process(&mut self) -> Result<()> {
        let blob = binaryblob::BinaryBlob::new(self._log_base, self._data.clone());
    
        let mut index: usize = 0;
        while index < self._log_length {
            let start = index;

            let (rtmr, pos) = blob.get_uint32(index)?;
            index = pos;
            let (etype, _) = blob.get_uint32(index)?;
    
            if rtmr == 0xFFFFFFFF {
                break;
            }
    
            if etype == tdeventlog::EV_NO_ACTION {
                self._specid_header.parse(self._data[start..].to_vec().clone())?;
                index = start + self._specid_header._base._length;
            }else{
                let mut event_log_obj = tdeventlog::TDEventLogEntry::new(self._log_base + start as u64, self._specid_header.clone());
                event_log_obj.parse(self._data[start..].to_vec())?;
                index = start + event_log_obj.length();
                self._event_logs.push(event_log_obj);
            }
        }

        Ok(())
    }

    fn replay(&mut self) -> Result<()> {
        // result dictionary for classifying event logs by rtmr index
        // the key is a integer, which represents rtmr index
        // the value is a list of event log entries whose rtmr index is equal to its related key
        let mut event_logs_by_index: HashMap<usize, Vec<tdeventlog::TDEventLogEntry>> = HashMap::new();

        for rtmr in 0..rtmr::RTMR_COUNT {
            event_logs_by_index.insert(rtmr, vec![]);
        }

        for event_log in self._event_logs.iter() {
            event_logs_by_index.get_mut(&(event_log._base._rtmr as usize)).unwrap().push(event_log.to_owned());
        }

        //let mut rtmr_by_index: HashMap<usize, rtmr::RTMR> = HashMap::new();
        for (rtmr_index, event_logs) in event_logs_by_index.iter() {
            let rtmr_value = TDEventLogActor::_replay_single_rtmr(event_logs);
            self._rtmrs.insert(rtmr_index.to_owned(), rtmr_value);
        }

        Ok(())
    }

    pub fn dump_td_event_logs(&mut self) -> Result<()>{
        let mut count: usize = 0;
        let mut start: usize = 0;

        info!("==== TDX Event Log Entry - {} [0x{:X}] ====", count, self._log_base + start as u64);
        self._specid_header.dump();
        count += 1;
        start += self._specid_header.length();

        for event_log in self._event_logs.iter() {
            info!("==== TDX Event Log Entry - {} [0x{:X}] ====", count, self._log_base + start as u64);
            event_log.dump();
            count += 1;
            start += event_log.length();
        }

        Ok(())
    }
    
    pub fn dump_rtmrs(&mut self) ->Result<()> {
        self.replay()?;

        for (rtmr_index, rtmr) in self._rtmrs.iter() {
            info!("==== RTMR{} ====", rtmr_index);
            rtmr.blob.dump();
            info!("");
        }

        Ok(())
    }

    pub fn rtmrs(&mut self) -> Result<Vec<Vec<u8>>> {
        self.replay()?;

        let mut hashes = vec![vec![]; rtmr::RTMR_COUNT];
        for (rtmr_index, rtmr) in self._rtmrs.iter() {
            hashes[rtmr_index.to_owned()] = rtmr.rtmr();
        }
        Ok(hashes)
    }
}
