package org.qortal.transaction;

import com.google.common.base.Utf8;
import org.qortal.account.Account;
import org.qortal.asset.Asset;
import org.qortal.block.BlockChain;
import org.qortal.controller.repository.NamesDatabaseIntegrityCheck;
import org.qortal.crypto.Crypto;
import org.qortal.data.naming.NameData;
import org.qortal.data.transaction.BuyNameTransactionData;
import org.qortal.data.transaction.TransactionData;
import org.qortal.naming.Name;
import org.qortal.repository.DataException;
import org.qortal.repository.Repository;
import org.qortal.utils.Unicode;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

public class BuyNameTransaction extends Transaction {

	// Properties

	private BuyNameTransactionData buyNameTransactionData;

	// Constructors

	public BuyNameTransaction(Repository repository, TransactionData transactionData) {
		super(repository, transactionData);

		this.buyNameTransactionData = (BuyNameTransactionData) this.transactionData;
	}

	// More information

	@Override
	public List<String> getRecipientAddresses() throws DataException {
		return Collections.singletonList(this.buyNameTransactionData.getSeller());
	}

	// Navigation

	public Account getBuyer() {
		return this.getCreator();
	}

	// Processing

	@Override
	public ValidationResult isValid() throws DataException {
		Optional<String> buyerPrimaryName = this.getBuyer().getPrimaryName();
		if( buyerPrimaryName.isPresent()  ) {

			NameData nameData = repository.getNameRepository().fromName(buyerPrimaryName.get());
			if (nameData.isForSale()) {
				return ValidationResult.NOT_SUPPORTED;
			}
		}

		String name = this.buyNameTransactionData.getName();

		// Check seller address is valid
		if (!Crypto.isValidAddress(this.buyNameTransactionData.getSeller()))
			return ValidationResult.INVALID_ADDRESS;

		// Check name size bounds
		int nameLength = Utf8.encodedLength(name);
		if (nameLength < Name.MIN_NAME_SIZE || nameLength > Name.MAX_NAME_SIZE)
			return ValidationResult.INVALID_NAME_LENGTH;

		// Check name is in normalized form (no leading/trailing whitespace, etc.)
		if (!name.equals(Unicode.normalize(name)))
			return ValidationResult.NAME_NOT_NORMALIZED;

		NameData nameData = this.repository.getNameRepository().fromName(name);

		// Check name exists
		if (nameData == null)
			return ValidationResult.NAME_DOES_NOT_EXIST;

		// Check name is currently for sale
		if (!nameData.isForSale())
			return ValidationResult.NAME_NOT_FOR_SALE;

		// Check buyer isn't trying to buy own name
		Account buyer = getBuyer();
		if (buyer.getAddress().equals(nameData.getOwner()))
			return ValidationResult.BUYER_ALREADY_OWNER;

		// If accounts are only allowed one registered name then check for this
		if (BlockChain.getInstance().oneNamePerAccount(this.repository.getBlockRepository().getBlockchainHeight())
				&& !this.repository.getNameRepository().getNamesByOwner(buyer.getAddress()).isEmpty())
			return ValidationResult.MULTIPLE_NAMES_FORBIDDEN;

		// Check expected seller currently owns name
		if (!this.buyNameTransactionData.getSeller().equals(nameData.getOwner()))
			return ValidationResult.INVALID_SELLER;

		// Check amounts agree
		if (this.buyNameTransactionData.getAmount() != nameData.getSalePrice())
			return ValidationResult.INVALID_AMOUNT;

		// Check buyer has enough funds
		if (buyer.getConfirmedBalance(Asset.QORT) < this.buyNameTransactionData.getFee() + this.buyNameTransactionData.getAmount())
			return ValidationResult.NO_BALANCE;

		return ValidationResult.OK;
	}

	@Override
	public void preProcess() throws DataException {
		BuyNameTransactionData buyNameTransactionData = (BuyNameTransactionData) transactionData;

		// Rebuild this name in the Names table from the transaction history
		// This is necessary because in some rare cases names can be missing from the Names table after registration
		// but we have been unable to reproduce the issue and track down the root cause
		NamesDatabaseIntegrityCheck namesDatabaseIntegrityCheck = new NamesDatabaseIntegrityCheck();
		namesDatabaseIntegrityCheck.rebuildName(buyNameTransactionData.getName(), this.repository);
	}

	@Override
	public void process() throws DataException {
		// Buy Name
		Name name = new Name(this.repository, this.buyNameTransactionData.getName());
		name.buy(this.buyNameTransactionData, true);

		// Save transaction with updated "name reference" pointing to previous transaction that changed name
		this.repository.getTransactionRepository().save(this.buyNameTransactionData);

		// if multiple names feature is activated, then check the buyer and seller's primary name status
		if( this.repository.getBlockRepository().getBlockchainHeight() > BlockChain.getInstance().getMultipleNamesPerAccountHeight()) {

			Account seller = new Account(this.repository, this.buyNameTransactionData.getSeller());
			Optional<String> sellerPrimaryName = seller.getPrimaryName();

			// if the seller sold their primary name, then remove their primary name
			if (sellerPrimaryName.isPresent() && sellerPrimaryName.get().equals(buyNameTransactionData.getName())) {
				seller.removePrimaryName();
			}

			Account buyer = new Account(this.repository, this.getBuyer().getAddress());

			// if the buyer had no primary name, then set the primary name to the name bought
			if( buyer.getPrimaryName().isEmpty() ) {
				buyer.setPrimaryName(this.buyNameTransactionData.getName());
			}
		}
	}

	@Override
	public void orphan() throws DataException {
		// Un-buy name
		Name name = new Name(this.repository, this.buyNameTransactionData.getName());
		name.unbuy(this.buyNameTransactionData);

		// Save this transaction, with previous "name reference"
		this.repository.getTransactionRepository().save(this.buyNameTransactionData);

		// if multiple names feature is activated, then check the buyer and seller's primary name status
		if( this.repository.getBlockRepository().getBlockchainHeight() > BlockChain.getInstance().getMultipleNamesPerAccountHeight()) {

			Account seller = new Account(this.repository, this.buyNameTransactionData.getSeller());

			// if the seller lost their primary name, then set their primary name back
			if (seller.getPrimaryName().isEmpty()) {
				seller.setPrimaryName(this.buyNameTransactionData.getName());
			}

			Account buyer = new Account(this.repository, this.getBuyer().getAddress());
			Optional<String> buyerPrimaryName = buyer.getPrimaryName();

			// if the buyer bought their primary, then remove it
			if( buyerPrimaryName.isPresent() && this.buyNameTransactionData.getName().equals(buyerPrimaryName.get()) ) {
				buyer.removePrimaryName();
			}
		}
	}
}
