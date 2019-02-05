use serde::{Serialize, Deserialize};

struct Response<T> {
    content: T,
    close: bool
}

impl<'de, T: Serialize + Deserialize<'de>> Response<T> {
    fn new(content: T, close: bool) -> Self {
        Self {
            content: content,
            close: close
        }
    }
    
    fn close(content: T) -> Self {
        Self::new(content, true)
    }
    
    fn ok(content: T) -> Self {
        Self::new(content, false)
    }
    
    fn encode(&self) -> ProtoResult<Response<Vec<u8>>> {
        to_bytes(&self.content).and_then(|v| to_bytes(&v))
                               .map(|v| Response::new(v, self.close))
    }
}

pub trait Handler {
    
}

pub struct Agent {
    handler: 
}