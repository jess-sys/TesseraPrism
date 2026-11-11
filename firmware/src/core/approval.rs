//! Approval broker: exactly one approval is on screen at a time (30 s timeout); further requests
//! queue (bounded) and are shown in order, anything beyond the bound is answered `Busy`.
use std::collections::VecDeque;
use std::sync::mpsc::SyncSender;
use std::time::{Duration, Instant};

use prism_core::model::EntryId;
use prism_ctap::PresenceResult;
use prism_proto::Request;
use prism_ui::ApprovalRequest;

use crate::transport::Link;

pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_QUEUED: usize = 4;

/// What to do once the user answered.
pub enum Done {
    Prism { link: Link, req_id: u32, req: Request, session_mark: Option<EntryId> },
    Ctap { link: Link, reply: SyncSender<PresenceResult> },
}

impl Done {
    pub fn link(&self) -> Link {
        match self {
            Done::Prism { link, .. } | Done::Ctap { link, .. } => *link,
        }
    }
}

pub struct Pending {
    pub ui: ApprovalRequest,
    pub done: Done,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Approved,
    Denied,
    Timeout,
    /// Device locked / link closed / host cancelled.
    Cancelled,
}

#[derive(Default)]
pub struct Broker {
    pub active: Option<(Pending, Instant)>,
    pub queue: VecDeque<Pending>,
    next_id: u32,
}

impl Broker {
    pub fn alloc_id(&mut self) -> u32 {
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.next_id
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.active.as_ref().map(|(_, started)| *started + APPROVAL_TIMEOUT)
    }

    pub fn queue_full(&self) -> bool {
        self.queue.len() >= MAX_QUEUED
    }
}
