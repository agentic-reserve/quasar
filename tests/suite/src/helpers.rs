use {
    quasar_svm::{
        token::{Mint, TokenAccount},
        Account, Pubkey, QuasarSvm,
    },
    solana_program_pack::Pack,
    spl_token_interface::state::AccountState,
};

// ---------------------------------------------------------------------------
// SVM factories
// ---------------------------------------------------------------------------

pub fn svm_validate() -> QuasarSvm {
    let elf = std::fs::read("../../target/deploy/quasar_test_token_validate.so").unwrap();
    QuasarSvm::new().with_program(&quasar_test_token_validate::ID, &elf)
}

pub fn svm_init() -> QuasarSvm {
    let elf = std::fs::read("../../target/deploy/quasar_test_token_init.so").unwrap();
    QuasarSvm::new().with_program(&quasar_test_token_init::ID, &elf)
}

pub fn svm_cpi() -> QuasarSvm {
    let elf = std::fs::read("../../target/deploy/quasar_test_token_cpi.so").unwrap();
    QuasarSvm::new().with_program(&quasar_test_token_cpi::ID, &elf)
}

// ---------------------------------------------------------------------------
// Program IDs
// ---------------------------------------------------------------------------

pub fn spl_token_program_id() -> Pubkey {
    quasar_svm::SPL_TOKEN_PROGRAM_ID
}

pub fn token_2022_program_id() -> Pubkey {
    quasar_svm::SPL_TOKEN_2022_PROGRAM_ID
}

pub fn ata_program_id() -> Pubkey {
    quasar_svm::SPL_ASSOCIATED_TOKEN_PROGRAM_ID
}

// ---------------------------------------------------------------------------
// Account constructors
// ---------------------------------------------------------------------------

pub fn token_account(
    address: Pubkey,
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    token_program: Pubkey,
) -> Account {
    quasar_svm::token::create_keyed_token_account_with_program(
        &address,
        &TokenAccount {
            mint,
            owner,
            amount,
            state: AccountState::Initialized,
            ..TokenAccount::default()
        },
        &token_program,
    )
}

pub fn token_account_with_delegate(
    address: Pubkey,
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    delegate: Pubkey,
    delegated_amount: u64,
    token_program: Pubkey,
) -> Account {
    quasar_svm::token::create_keyed_token_account_with_program(
        &address,
        &TokenAccount {
            mint,
            owner,
            amount,
            delegate: Some(delegate).into(),
            state: AccountState::Initialized,
            delegated_amount,
            ..TokenAccount::default()
        },
        &token_program,
    )
}

pub fn mint_account(
    address: Pubkey,
    authority: Pubkey,
    decimals: u8,
    token_program: Pubkey,
) -> Account {
    quasar_svm::token::create_keyed_mint_account_with_program(
        &address,
        &Mint {
            mint_authority: Some(authority).into(),
            supply: 1_000_000_000,
            decimals,
            is_initialized: true,
            freeze_authority: None.into(),
        },
        &token_program,
    )
}

pub fn mint_account_with_freeze(
    address: Pubkey,
    authority: Pubkey,
    decimals: u8,
    freeze_authority: Pubkey,
    token_program: Pubkey,
) -> Account {
    quasar_svm::token::create_keyed_mint_account_with_program(
        &address,
        &Mint {
            mint_authority: Some(authority).into(),
            supply: 1_000_000_000,
            decimals,
            is_initialized: true,
            freeze_authority: Some(freeze_authority).into(),
        },
        &token_program,
    )
}

pub fn signer_account(address: Pubkey) -> Account {
    quasar_svm::token::create_keyed_system_account(&address, 1_000_000)
}

pub fn rich_signer_account(address: Pubkey) -> Account {
    quasar_svm::token::create_keyed_system_account(&address, 100_000_000_000)
}

pub fn empty_account(address: Pubkey) -> Account {
    Account {
        address,
        lamports: 0,
        data: vec![],
        owner: quasar_svm::system_program::ID,
        executable: false,
    }
}

// ---------------------------------------------------------------------------
// Raw data packing (for adversarial tests)
// ---------------------------------------------------------------------------

pub fn pack_token_data(mint: Pubkey, owner: Pubkey, amount: u64) -> Vec<u8> {
    let token = TokenAccount {
        mint,
        owner,
        amount,
        state: AccountState::Initialized,
        ..TokenAccount::default()
    };
    let mut data = vec![0u8; TokenAccount::LEN];
    Pack::pack(token, &mut data).unwrap();
    data
}

pub fn pack_mint_data(authority: Pubkey, decimals: u8) -> Vec<u8> {
    let mint = Mint {
        mint_authority: Some(authority).into(),
        supply: 1_000_000_000,
        decimals,
        is_initialized: true,
        freeze_authority: None.into(),
    };
    let mut data = vec![0u8; Mint::LEN];
    Pack::pack(mint, &mut data).unwrap();
    data
}

pub fn pack_mint_data_with_freeze(
    authority: Pubkey,
    decimals: u8,
    freeze_authority: Pubkey,
) -> Vec<u8> {
    let mint = Mint {
        mint_authority: Some(authority).into(),
        supply: 1_000_000_000,
        decimals,
        is_initialized: true,
        freeze_authority: Some(freeze_authority).into(),
    };
    let mut data = vec![0u8; Mint::LEN];
    Pack::pack(mint, &mut data).unwrap();
    data
}

/// Raw Account with custom data — for adversarial tests (wrong owner, bad data, etc.)
pub fn raw_account(address: Pubkey, lamports: u64, data: Vec<u8>, owner: Pubkey) -> Account {
    Account {
        address,
        lamports,
        data,
        owner,
        executable: false,
    }
}
