use teos_common::appointment::Appointment;
use teos_common::cryptography::recover_pk;
use teos_common::receipts::{AppointmentReceipt, RegistrationReceipt};
use teos_common::{TowerId, UserId};

#[derive(Debug)]
pub enum ReceiptCheckError {
    ReceiptVerificationFailed,
    AppointmentOutsideSubscription,
}

pub fn check_signature(
    appointment: &Appointment,
    signature: &str,
    user_id: &UserId,
) -> Result<bool, ReceiptCheckError> {
    let recovered_id = recover_pk(&appointment.to_vec(), signature).unwrap();
    Ok(recovered_id == user_id.0)
}

pub fn check_receipts(
    user_id: &UserId,
    tower_id: &TowerId,
    reg_receipt: &RegistrationReceipt,
    app_receipt: &AppointmentReceipt,
    appointment: &Appointment,
    user_signature: &str,
) -> Result<bool, ReceiptCheckError> {
    // Check if the receipts are signed by user and tower
    let reg_receipt_check = reg_receipt.verify(&tower_id);
    let user_signature_check = check_signature(appointment, user_signature, user_id)?;

    // Now check the tower's signature on the user's signature
    let recovered_id =
        TowerId(recover_pk(user_signature.as_bytes(), &app_receipt.signature().unwrap()).unwrap());
    let app_receipt_check = recovered_id == *tower_id;

    // Print the results of the checks for debugging
    println!("reg_receipt_check: {}", reg_receipt_check);
    println!("user_signature_check: {}", user_signature_check);
    println!("app_receipt_check: {}", app_receipt_check);

    if !reg_receipt_check || !user_signature_check || !app_receipt_check {
        return Err(ReceiptCheckError::ReceiptVerificationFailed);
    }

    // Check if the appointment is covered by the subscription
    let appointment_in_subscription = app_receipt.start_block() >= reg_receipt.subscription_start()
        && app_receipt.start_block() <= reg_receipt.subscription_expiry();

    // Print the results of the subscription check for debugging
    println!("subscription start: {}", reg_receipt.subscription_start());
    println!("subscription expiry: {}", reg_receipt.subscription_expiry());
    println!("appointment start block: {}", app_receipt.start_block());
    println!(
        "appointment in subscription: {}",
        appointment_in_subscription
    );

    if !appointment_in_subscription {
        return Err(ReceiptCheckError::AppointmentOutsideSubscription);
    }

    // If everything is fine, return true
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use teos_common::cryptography::{get_random_keypair, sign};
    use teos_common::test_utils::{generate_random_appointment, get_random_registration_receipt};
    use teos_common::TowerId;

    #[test]
    fn test_check_receipts_valid() {
        // Generate the user and tower key pairs.
        let (user_sk, user_pk) = get_random_keypair();
        let (tower_sk, tower_pk) = get_random_keypair();

        let user_id = UserId(user_pk);
        let tower_id = TowerId(tower_pk);

        // Generate a registration receipt and ensure it's signed by the tower.
        let mut reg_receipt = get_random_registration_receipt();
        reg_receipt.sign(&tower_sk);

        // Generate a random appointment and sign it with the user's secret key
        let appointment = generate_random_appointment(None);
        let user_signature = sign(&appointment.to_vec(), &user_sk).unwrap();

        // Ensure the appointment receipt's start block is within the subscription period.
        let start_block = reg_receipt.subscription_start() + 1; // A block after subscription start.

        // Use the actual signature of the appointment in the appointment receipt
        let mut app_receipt = AppointmentReceipt::new(user_signature.clone(), start_block);
        app_receipt.sign(&tower_sk); // Tower signs the receipt

        let result = check_receipts(
            &user_id,
            &tower_id,
            &reg_receipt,
            &app_receipt,
            &appointment,
            &user_signature,
        );
        if result.is_err() {
            println!("Error: {:?}", result);
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_receipts_invalid() {
        // Generate the user and tower key pairs.
        let (user_sk, user_pk) = get_random_keypair();
        let (tower_sk, tower_pk) = get_random_keypair();

        let user_id = UserId(user_pk);
        let tower_id = TowerId(tower_pk);

        // Generate a registration receipt and ensure it's signed by the tower.
        let mut reg_receipt = get_random_registration_receipt();
        reg_receipt.sign(&tower_sk);

        // Generate a random appointment and sign it with the user's secret key
        let appointment = generate_random_appointment(None);
        let user_signature = sign(&appointment.to_vec(), &user_sk).unwrap();

        // Generate an appointment receipt with a start block that is not within the subscription period.
        let start_block = reg_receipt.subscription_expiry() + 1; // A block after subscription expiry.

        let mut app_receipt = AppointmentReceipt::new(user_signature.clone(), start_block);
        app_receipt.sign(&tower_sk); // Use the tower's secret key to sign

        let result = check_receipts(
            &user_id,
            &tower_id,
            &reg_receipt,
            &app_receipt,
            &appointment,
            &user_signature,
        );
        if result.is_err() {
            println!("Error: {:?}", result);
        }
        assert!(result.is_err());
    }
}