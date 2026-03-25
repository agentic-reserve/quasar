use {
    crate::helpers::*,
    quasar_svm::{Instruction, Pubkey},
    quasar_test_token_init::client::*,
};

// ===========================================================================
// PDA init mint — SPL Token
// ===========================================================================

#[test]
fn init_mint_pda_spl_happy() {
    let mut svm = svm_init();
    let payer = Pubkey::new_unique();
    let token_program = spl_token_program_id();
    let system_program = quasar_svm::system_program::ID;

    let (mint_pda, _bump) = Pubkey::find_program_address(
        &[b"mint", payer.as_ref()],
        &quasar_test_token_init::ID,
    );

    let instruction: Instruction = InitMintPdaInstruction {
        payer,
        mint: mint_pda,
        token_program,
        system_program,
    }
    .into();

    let result = svm.process_instruction(
        &instruction,
        &[rich_signer_account(payer), empty_account(mint_pda)],
    );
    assert!(
        result.is_ok(),
        "init mint PDA should succeed: {:?}",
        result.raw_result
    );
}

#[test]
fn init_mint_pda_spl_wrong_address() {
    let mut svm = svm_init();
    let payer = Pubkey::new_unique();
    let token_program = spl_token_program_id();
    let system_program = quasar_svm::system_program::ID;

    let wrong_key = Pubkey::new_unique();

    let instruction: Instruction = InitMintPdaInstruction {
        payer,
        mint: wrong_key,
        token_program,
        system_program,
    }
    .into();

    let result = svm.process_instruction(
        &instruction,
        &[rich_signer_account(payer), empty_account(wrong_key)],
    );
    assert!(
        result.is_err(),
        "init mint PDA with wrong address should fail"
    );
}

// ===========================================================================
// PDA init mint — Token-2022
// ===========================================================================

#[test]
fn init_mint_pda_t22_happy() {
    let mut svm = svm_init();
    let payer = Pubkey::new_unique();
    let token_program = token_2022_program_id();
    let system_program = quasar_svm::system_program::ID;

    let (mint_pda, _bump) = Pubkey::find_program_address(
        &[b"mint", payer.as_ref()],
        &quasar_test_token_init::ID,
    );

    let instruction: Instruction = InitMintPdaT22Instruction {
        payer,
        mint: mint_pda,
        token_program,
        system_program,
    }
    .into();

    let result = svm.process_instruction(
        &instruction,
        &[rich_signer_account(payer), empty_account(mint_pda)],
    );
    assert!(
        result.is_ok(),
        "init mint PDA (T22) should succeed: {:?}",
        result.raw_result
    );
}

#[test]
fn init_mint_pda_t22_wrong_address() {
    let mut svm = svm_init();
    let payer = Pubkey::new_unique();
    let token_program = token_2022_program_id();
    let system_program = quasar_svm::system_program::ID;

    let wrong_key = Pubkey::new_unique();

    let instruction: Instruction = InitMintPdaT22Instruction {
        payer,
        mint: wrong_key,
        token_program,
        system_program,
    }
    .into();

    let result = svm.process_instruction(
        &instruction,
        &[rich_signer_account(payer), empty_account(wrong_key)],
    );
    assert!(
        result.is_err(),
        "init mint PDA (T22) with wrong address should fail"
    );
}
