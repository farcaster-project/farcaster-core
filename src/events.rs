pub trait EventCore {
    fn id(&self) -> i32;
}

#[derive(Debug, Clone)]
pub struct HeightChanged {
    pub id: i32,
    pub block: Vec<u8>,
    pub height: u64,
}

impl EventCore for HeightChanged {
    fn id(&self) -> i32 {
        self.id
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    HeightChanged,
}
