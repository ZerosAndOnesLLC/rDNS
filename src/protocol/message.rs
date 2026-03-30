use super::header::{Header, HeaderError, HEADER_SIZE};
use super::record::{Question, QuestionError, RecordError, ResourceRecord};

/// A complete DNS message (query or response).
#[derive(Debug, Clone)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authority: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
}

#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("header error: {0}")]
    Header(#[from] HeaderError),

    #[error("question error: {0}")]
    Question(#[from] QuestionError),

    #[error("record error: {0}")]
    Record(#[from] RecordError),

    #[error("message too large: {0} bytes")]
    TooLarge(usize),
}

/// Maximum UDP DNS message size (without EDNS)
pub const MAX_UDP_SIZE: usize = 512;

/// Maximum DNS message size (with EDNS, typical)
pub const MAX_EDNS_SIZE: usize = 4096;

impl Message {
    /// Decode a DNS message from wire format.
    pub fn decode(buf: &[u8]) -> Result<Self, MessageError> {
        let header = Header::decode(buf)?;

        let mut offset = HEADER_SIZE;

        // Decode questions
        let mut questions = Vec::with_capacity(header.qd_count as usize);
        for _ in 0..header.qd_count {
            let (q, consumed) = Question::decode(buf, offset)?;
            offset += consumed;
            questions.push(q);
        }

        // Decode answers
        let mut answers = Vec::with_capacity(header.an_count as usize);
        for _ in 0..header.an_count {
            let (rr, consumed) = ResourceRecord::decode(buf, offset)?;
            offset += consumed;
            answers.push(rr);
        }

        // Decode authority
        let mut authority = Vec::with_capacity(header.ns_count as usize);
        for _ in 0..header.ns_count {
            let (rr, consumed) = ResourceRecord::decode(buf, offset)?;
            offset += consumed;
            authority.push(rr);
        }

        // Decode additional
        let mut additional = Vec::with_capacity(header.ar_count as usize);
        for _ in 0..header.ar_count {
            let (rr, consumed) = ResourceRecord::decode(buf, offset)?;
            offset += consumed;
            additional.push(rr);
        }

        Ok(Self {
            header,
            questions,
            answers,
            authority,
            additional,
        })
    }

    /// Encode this message to wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        self.header.encode(&mut buf);

        for q in &self.questions {
            q.encode(&mut buf);
        }
        for rr in &self.answers {
            rr.encode(&mut buf);
        }
        for rr in &self.authority {
            rr.encode(&mut buf);
        }
        for rr in &self.additional {
            rr.encode(&mut buf);
        }

        buf
    }

    /// Build a SERVFAIL response for a given query.
    pub fn servfail(query: &Message) -> Self {
        Self {
            header: Header::servfail_response(&query.header),
            questions: query.questions.clone(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// Build a FORMERR response for a malformed query.
    pub fn formerr(id: u16) -> Self {
        use super::opcode::Opcode;
        use super::rcode::Rcode;

        Self {
            header: Header {
                id,
                qr: true,
                opcode: Opcode::Query,
                aa: false,
                tc: false,
                rd: false,
                ra: true,
                ad: false,
                cd: false,
                rcode: Rcode::FormErr,
                qd_count: 0,
                an_count: 0,
                ns_count: 0,
                ar_count: 0,
            },
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }
}
