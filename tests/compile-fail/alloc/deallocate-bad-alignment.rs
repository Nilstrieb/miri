use std::alloc::{alloc, dealloc, Layout};

// error-pattern: has size 1 and alignment ALIGN, but gave size 1 and alignment ALIGN

fn main() {
    unsafe {
        let x = alloc(Layout::from_size_align_unchecked(1, 1));
        dealloc(x, Layout::from_size_align_unchecked(1, 2));
    }
}
