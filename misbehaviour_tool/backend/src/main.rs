mod tool;

use teos_common::cryptography::{get_random_keypair, sign};
use teos_common::receipts::AppointmentReceipt;
use teos_common::test_utils::{generate_random_appointment, get_random_registration_receipt};
use teos_common::TowerId;
use teos_common::UserId;

fn main() {
    let (user_sk, user_pk) = get_random_keypair();
    let user_id = UserId(user_pk);
    let (tower_sk, tower_pk) = get_random_keypair();
    let tower_id = TowerId(tower_pk);

    println!("User secret key: {:?}", user_sk);
    println!("User public key: {:?}", user_pk);
    println!("Tower secret key: {:?}", tower_sk);
    println!("Tower public key: {:?}", tower_pk);

    let mut reg_receipt = get_random_registration_receipt();
    println!("Registration Receipt before sign: {:?}", reg_receipt);
    reg_receipt.sign(&tower_sk);
    println!("Registration Receipt after sign: {:?}", reg_receipt);

    // Generate a random appointment and sign it with the user's secret key
    let appointment = generate_random_appointment(None);
    let user_signature = sign(&appointment.to_vec(), &user_sk).unwrap();

    let start_block = reg_receipt.subscription_start() + 1; // A block after subscription start.

    let mut app_receipt = AppointmentReceipt::new(user_signature.clone(), start_block);
    println!("Appointment Receipt before sign: {:?}", app_receipt);
    app_receipt.sign(&tower_sk); // Use the tower's secret key to sign
    println!("Appointment Receipt after sign: {:?}", app_receipt);

    match tool::check_receipts(
        &user_id,
        &tower_id,
        &reg_receipt,
        &app_receipt,
        &appointment,
        &user_signature,
    ) {
        Ok(_) => println!("Receipts check out!"),
        Err(e) => eprintln!("Receipt check failed: {:?}", e),
    }
}