#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

use std::time::Instant;
use core::fmt::Write;
use graphics_server::api::GlyphStyle;
use graphics_server::{DrawStyle, Gid, PixelColor, Point, Rectangle, TextBounds, TextView};
use num_traits::*;
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};


pub(crate) const SERVER_NAME_SHA512: &str = "_sha512_";

#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub(crate) enum sha512Op {
    /// Redraw the screen
    Redraw = 0,

    /// Quit the application
    Quit,
}

struct sha512 {
    content: Gid,
    gam: gam::Gam,
    _gam_token: [u32; 4],
    screensize: Point,
    #[cfg(feature = "tts")]
    tts: TtsFrontend,
}

impl sha512 {
    fn new(xns: &xous_names::XousNames, sid: xous::SID) -> Self {
        let gam = gam::Gam::new(&xns).expect("Can't connect to GAM");
        let gam_token = gam
            .register_ux(gam::UxRegistration {
                app_name: xous_ipc::String::<128>::from_str(gam::APP_NAME_SHA512),
                ux_type: gam::UxType::Chat,
                predictor: None,
                listener: sid.to_array(),
                redraw_id: sha512Op::Redraw.to_u32().unwrap(),
                gotinput_id: None,
                audioframe_id: None,
                rawkeys_id: None,
                focuschange_id: None,
            })
            .expect("Could not register GAM UX")
            .unwrap();

        let content = gam
            .request_content_canvas(gam_token)
            .expect("Could not get content canvas");
        let screensize = gam
            .get_canvas_bounds(content)
            .expect("Could not get canvas dimensions");
        Self {
            gam,
            _gam_token: gam_token,
            content,
            screensize,
        }
    }

    /// Clear the entire screen.
    fn clear_area(&self) {
        self.gam
            .draw_rectangle(
                self.content,
                Rectangle::new_with_style(
                    Point::new(0, 0),
                    self.screensize,
                    DrawStyle {
                        fill_color: Some(PixelColor::Light),
                        stroke_color: None,
                        stroke_width: 0,
                    },
                ),
            )
            .expect("can't clear content area");
    }

    /// Redraw the text view onto the screen.
    fn redraw(&mut self, keygen_time: u128, cipherblock_time: u128, ciphertext_decrypt: u128) {
        self.clear_area();

        let mut text_view = TextView::new(
            self.content,
            TextBounds::GrowableFromBr(
                Point::new(
                    self.screensize.x - (self.screensize.x / 2),
                    self.screensize.y - (self.screensize.y / 2),
                ),
                (self.screensize.x / 5 * 4) as u16,
            ),
        );

        text_view.border_width = 1;
        text_view.draw_border = true;
        text_view.clear_area = true;
        text_view.rounded_border = Some(3);
        text_view.style = GlyphStyle::Regular;
        write!(text_view.text, "{}", keygen_time).expect("Could not write to text view");

        let mut tv2 = TextView::new(
            self.content,
            TextBounds::GrowableFromBr(
                Point::new(
                    self.screensize.x - (self.screensize.x / 2),
                    self.screensize.y - (self.screensize.y / 3),
                ),
                (self.screensize.x / 5 * 4) as u16,
            ),
        );

        tv2.border_width = 1;
        tv2.draw_border = true;
        tv2.clear_area = true;
        tv2.rounded_border = Some(3);
        tv2.style = GlyphStyle::Regular;
        write!(tv2.text, "{}", cipherblock_time).expect("Could not write to text view");

        let mut tv3 = TextView::new(
            self.content,
            TextBounds::GrowableFromBr(
                Point::new(
                    self.screensize.x - (self.screensize.x / 2),
                    self.screensize.y - (self.screensize.y / 4),
                ),
                (self.screensize.x / 5 * 4) as u16,
            ),
        );

        tv3.border_width = 1;
        tv3.draw_border = true;
        tv3.clear_area = true;
        tv3.rounded_border = Some(3);
        tv3.style = GlyphStyle::Regular;
        write!(tv3.text, "{}", ciphertext_decrypt).expect("Could not write to text view");

        self.gam
            .post_textview(&mut text_view)
            .expect("Could not render text view");

        self.gam
            .post_textview(&mut tv2)
            .expect("Could not render text view");

        self.gam
            .post_textview(&mut tv3)
            .expect("Could not render text view");
        self.gam.redraw().expect("Could not redraw screen");
        }
    

}

fn main() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("sha512 world PID is {}", xous::process::id());
    // Random sleep to simulate print functions 


    // SHA256 BENCHMARK
    // let mut sha256_time: u128 = 0;
    // let charset = "1234567890";
    // for _ in 1..1000001 {
    //     // Generate random string
    //     let r_str = generate(8, charset);
    //     // Run sha256 and calculate time 
    //     let start = Instant::now();
    //     let mut hash_256 = Sha256::new();
    //     hash_256.update(r_str.as_bytes());
    //     hash_256.finalize();
    //     let duration = start.elapsed();
    //     sha256_time = sha256_time + duration.as_nanos();
    // }


    // SHA512 BENCHMARK
    // let mut sha512_time: u128 = 0;
    // for _ in 1..1000001 {
    //     // Generate random string
    //     let r_str = generate(8, charset);
    //     // Run sha512 and calculate time 
    //     let start = Instant::now();
    //     let hash_512 = Sha512::new();
    //     hash_512.update(r_str.as_bytes());
    //     hash_512.finalize();
    //     let duration = start.elapsed();
    //     sha512_time = sha512_time + duration.as_nanos();
    // }

    // AES KEYGEN
    let mut aes_keygen_time: u128 = 0;
    for _ in 1..1000001 {
        let start = Instant::now();
        let key = GenericArray::from([0u8; 16]);
        Aes128::new(&key);
        let duration = start.elapsed();
        aes_keygen_time = aes_keygen_time + duration.as_nanos();    
    }


    // // AES CIPHERBLOCK
    let mut aes_cipherblock_time: u128 = 0;
    let key = GenericArray::from([0u8; 16]);
    let cipher = Aes128::new(&key);
    let block = GenericArray::from([42u8; 16]);
    for _ in 1..1000001 {
        let mut blocks = [block; 100];
        let start = Instant::now();
        cipher.encrypt_blocks(&mut blocks);
        let duration = start.elapsed();
        aes_cipherblock_time = aes_cipherblock_time + duration.as_nanos();    
    }

    // // AES DECRYPT
    let mut aes_decrypt: u128 = 0;
    let key = GenericArray::from([0u8; 16]);
    let cipher = Aes128::new(&key);
    let block = GenericArray::from([42u8; 16]);
    for _ in 1..256 {
        let mut blocks = [block; 100];
        cipher.encrypt_blocks(&mut blocks);
        let start = Instant::now();
        cipher.decrypt_blocks(&mut blocks);
        let duration = start.elapsed();
        aes_decrypt = aes_decrypt + duration.as_nanos();    
    }


    let xns = xous_names::XousNames::new().unwrap();

    // Register the server with xous
    let sid = xns
        .register_name(SERVER_NAME_SHA512, None)
        .expect("can't register server");

    let mut hello = sha512::new(&xns, sid);


    loop {
        let msg = xous::receive_message(sid).unwrap();
        log::debug!("Got message: {:?}", msg);

        match FromPrimitive::from_usize(msg.body.id()) {
            Some(sha512Op::Redraw) => {
                log::debug!("Got redraw");
                hello.redraw(aes_keygen_time, aes_cipherblock_time, aes_decrypt);
            }
            Some(sha512Op::Quit) => {
                log::info!("Quitting application");
                break;
            }
            _ => {
                log::error!("Got unknown message");
            }
        }
    }

    log::info!("Quitting");
    xous::terminate_process(0)
}
