//! Mock AMM for LiteSVM money-path tests of fortiblox-router v2.
//!
//! One program deployed at BOTH `xdex::ID` and `degen::ID`. It faithfully
//! reproduces the OBSERVABLE effects the router measures — nothing more:
//!   * `sell` (Degen): pull `amount` meme tokens signer->curve vault; credit
//!     native `payout` to the signer; CLOSE the signer WXNT ATA (reclaim rent),
//!     exactly like live Degen. `payout` gets a +5% rebate when signer==creator.
//!   * `swap_base_input` (XDEX): pull `amount_in` from the user input ATA to the
//!     input vault; deliver `amount_in` output tokens from the output vault.
//! Meme/output tokens are CLASSIC SPL here (Token-2022 is only a stub in this
//! LiteSVM); the router treats them as generic token accounts, so the native /
//! wrap / fee / min-out logic under test is identical.
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
    instruction::{AccountMeta, Instruction},
};

const SELL_DISC: [u8; 8] = [51, 230, 133, 164, 1, 127, 131, 173];
const SWAP_DISC: [u8; 8] = [143, 190, 90, 218, 196, 30, 51, 222];

entrypoint!(process);

fn amt(data: &[u8]) -> Result<u64, ProgramError> {
    let mut b = [0u8; 8];
    b.copy_from_slice(data.get(8..16).ok_or(ProgramError::InvalidInstructionData)?);
    Ok(u64::from_le_bytes(b))
}

fn spl_transfer<'a>(prog: &AccountInfo<'a>, src: &AccountInfo<'a>, dst: &AccountInfo<'a>, auth: &AccountInfo<'a>, amount: u64) -> ProgramResult {
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    let ix = Instruction {
        program_id: *prog.key,
        accounts: vec![
            AccountMeta::new(*src.key, false),
            AccountMeta::new(*dst.key, false),
            AccountMeta::new_readonly(*auth.key, true),
        ],
        data,
    };
    invoke(&ix, &[src.clone(), dst.clone(), auth.clone(), prog.clone()])
}

fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let disc = data.get(0..8).ok_or(ProgramError::InvalidInstructionData)?;

    if disc == SELL_DISC {
        let amount = amt(data)?;
        let ai = accounts;
        let signer = &ai[0];
        let creator = &ai[3];
        let token_state = &ai[6];
        let signer_meme = &ai[7];
        let signer_wsol = &ai[8];
        let vault_meme = &ai[9];
        let token_program = &ai[12];

        // 1. meme in: signer meme ATA -> curve meme vault (authority = signer).
        spl_transfer(token_program, signer_meme, vault_meme, signer, amount)?;

        // 2. auto-unwrap: CLOSE the signer WXNT ATA (rent + any balance -> signer).
        //    Done via CPI FIRST, while the mock's accounts are still balanced.
        let close = Instruction {
            program_id: *token_program.key,
            accounts: vec![
                AccountMeta::new(*signer_wsol.key, false),
                AccountMeta::new(*signer.key, false),
                AccountMeta::new_readonly(*signer.key, true),
            ],
            data: vec![9u8],
        };
        invoke(&close, &[signer_wsol.clone(), signer.clone(), signer.clone(), token_program.clone()])?;

        // 3. payout native (+5% rebate if the seller is the curve creator). Direct
        //    lamport move (curve is mock-owned) done LAST — no CPI follows, so the
        //    only balance check is at instruction end, where it nets to zero.
        let payout = if signer.key == creator.key { amount + amount / 20 } else { amount };
        **token_state.try_borrow_mut_lamports()? = token_state
            .lamports()
            .checked_sub(payout)
            .ok_or(ProgramError::InsufficientFunds)?;
        **signer.try_borrow_mut_lamports()? = signer.lamports().checked_add(payout).unwrap();
        return Ok(());
    }

    if disc == SWAP_DISC {
        let amount_in = amt(data)?;
        let mut it = accounts.iter();
        let payer = next_account_info(&mut it)?; // 0
        let _authority = next_account_info(&mut it)?; // 1
        let _amm_config = next_account_info(&mut it)?; // 2
        let _pool = next_account_info(&mut it)?; // 3
        let input_ata = next_account_info(&mut it)?; // 4
        let output_ata = next_account_info(&mut it)?; // 5
        let input_vault = next_account_info(&mut it)?; // 6
        let output_vault = next_account_info(&mut it)?; // 7
        let in_prog = next_account_info(&mut it)?; // 8
        let out_prog = next_account_info(&mut it)?; // 9

        // input: user input ATA -> input vault (authority = payer/user).
        spl_transfer(in_prog, input_ata, input_vault, payer, amount_in)?;

        // output: output vault -> user output ATA, 1:1. The mock's output vault is
        // set up with the user as its token-account authority, so the user (a
        // signer) authorizes the release — no PDA needed for the harness.
        spl_transfer(out_prog, output_vault, output_ata, payer, amount_in)?;
        return Ok(());
    }

    Err(ProgramError::InvalidInstructionData)
}
