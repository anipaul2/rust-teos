#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

use rocket::{post, Data};
use rocket_contrib::json::Json;
use serde::{Deserialize, Serialize};

use crate::tool::{check_receipts, ReceiptCheckError};
use teos_common::appointment::Appointment;
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::{TowerId, UserId};

#[derive(Serialize, Deserialize)]
struct ReceiptData {
    user_id: UserId,
    tower_id: TowerId,
    reg_receipt: RegistrationReceipt,
    app_receipt: AppointmentReceipt,
    appointment: Appointment,
    user_signature: String,
}

#[derive(Serialize, Deserialize)]
struct ReceiptCheckResult {
    success: bool,
    error: Option<String>,
}

#[post("/check", format = "json", data = "<data>")]
fn check(data: Json<ReceiptData>) -> Json<ReceiptCheckResult> {
    let result = check_receipts(
        &data.user_id,
        &data.tower_id,
        &data.reg_receipt,
        &data.app_receipt,
        &data.appointment,
        &data.user_signature,
    );

    match result {
        Ok(_) => Json(ReceiptCheckResult { success: true, error: None }),
        Err(e) => Json(ReceiptCheckResult { success: false, error: Some(format!("{:?}", e)) }),
    }
}

pub fn run_api() {
    rocket::ignite()
        .mount("/", routes![check])
        .launch();
}