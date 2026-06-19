/**
 * Cashu payment verification.
 *
 * Stubbed for now — wire up with cashu-ts v4 locally.
 *
 * v4 pattern (from cashutools-dev):
 *   import { Wallet, getTokenMetadata } from '@cashu/cashu-ts';
 *   const meta = getTokenMetadata(token);  // pre-wallet: mint, unit, amount
 *   const wallet = new Wallet(meta.mint, { unit: 'sat' });
 *   await wallet.loadMint();
 *   const proofs = await wallet.receive(token);  // swap = burn old, get fresh
 *
 * Key v4 gotchas:
 *   - Proof.amount is bigint, not number
 *   - getDecodedToken() needs keysetIds; use getTokenMetadata() for pre-check
 *   - wallet.loadMint() is mandatory before any ops
 *   - v4 is ESM-only
 */

export interface PaymentResult {
  valid: boolean;
  amountSats: number;
  error?: string;
}

/**
 * Verify and receive a Cashu token.
 *
 * In dry-run mode this is never called. In live mode:
 * 1. Decode token, check mint is accepted, check amount >= price
 * 2. wallet.receive() to swap proofs (prevents double-spend)
 * 3. Return result
 */
export async function receivePayment(
  _encodedToken: string,
  _acceptedMints: string[],
  _requiredSats: number
): Promise<PaymentResult> {
  // TODO: implement with cashu-ts v4
  // See docstring above for the pattern
  throw new Error('Cashu payment not yet wired — implement with cashu-ts v4');
}
