package org.qora.transaction;

import java.math.BigDecimal;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.qora.account.Account;
import org.qora.account.PublicKeyAccount;
import org.qora.asset.Asset;
import org.qora.data.transaction.GroupApprovalTransactionData;
import org.qora.data.transaction.TransactionData;
import org.qora.repository.DataException;
import org.qora.repository.Repository;

public class GroupApprovalTransaction extends Transaction {

	// Properties
	private GroupApprovalTransactionData groupApprovalTransactionData;

	// Constructors

	public GroupApprovalTransaction(Repository repository, TransactionData transactionData) {
		super(repository, transactionData);

		this.groupApprovalTransactionData = (GroupApprovalTransactionData) this.transactionData;
	}

	// More information

	@Override
	public List<Account> getRecipientAccounts() throws DataException {
		return Collections.emptyList();
	}

	@Override
	public boolean isInvolved(Account account) throws DataException {
		String address = account.getAddress();

		if (address.equals(this.getAdmin().getAddress()))
			return true;

		return false;
	}

	@Override
	public BigDecimal getAmount(Account account) throws DataException {
		String address = account.getAddress();
		BigDecimal amount = BigDecimal.ZERO.setScale(8);

		if (address.equals(this.getAdmin().getAddress()))
			amount = amount.subtract(this.transactionData.getFee());

		return amount;
	}

	// Navigation

	public Account getAdmin() throws DataException {
		return new PublicKeyAccount(this.repository, this.groupApprovalTransactionData.getAdminPublicKey());
	}

	// Processing

	@Override
	public ValidationResult isValid() throws DataException {
		// Grab pending transaction's data
		TransactionData pendingTransactionData = this.repository.getTransactionRepository().fromSignature(groupApprovalTransactionData.getPendingSignature());
		if (pendingTransactionData == null)
			return ValidationResult.TRANSACTION_UNKNOWN;

		// Check pending transaction's groupID matches our transaction's groupID
		if (groupApprovalTransactionData.getTxGroupId() != pendingTransactionData.getTxGroupId())
			return ValidationResult.GROUP_ID_MISMATCH;

		// Check pending transaction is not already in a block
		if (this.repository.getTransactionRepository().getHeightFromSignature(groupApprovalTransactionData.getPendingSignature()) != 0)
			return ValidationResult.TRANSACTION_ALREADY_CONFIRMED;

		Account admin = getAdmin();

		// Can't cast approval decision if not an admin
		if (!this.repository.getGroupRepository().adminExists(groupApprovalTransactionData.getTxGroupId(), admin.getAddress()))
			return ValidationResult.NOT_GROUP_ADMIN;

		// Check fee is positive
		if (groupApprovalTransactionData.getFee().compareTo(BigDecimal.ZERO) <= 0)
			return ValidationResult.NEGATIVE_FEE;

		// Check reference
		if (!Arrays.equals(admin.getLastReference(), groupApprovalTransactionData.getReference()))
			return ValidationResult.INVALID_REFERENCE;

		// Check creator has enough funds
		if (admin.getConfirmedBalance(Asset.QORA).compareTo(groupApprovalTransactionData.getFee()) < 0)
			return ValidationResult.NO_BALANCE;

		return ValidationResult.OK;
	}

	@Override
	public void process() throws DataException {
		// Find previous approval decision (if any) by this admin for pending transaction
		List<GroupApprovalTransactionData> approvals = this.repository.getTransactionRepository().getLatestApprovals(groupApprovalTransactionData.getPendingSignature(), groupApprovalTransactionData.getAdminPublicKey());
		
		if (!approvals.isEmpty())
			groupApprovalTransactionData.setPriorReference(approvals.get(0).getSignature());

		// Save this transaction with updated prior reference to transaction that can help restore state
		this.repository.getTransactionRepository().save(groupApprovalTransactionData);

		// Update admin's balance
		Account admin = getAdmin();
		admin.setConfirmedBalance(Asset.QORA, admin.getConfirmedBalance(Asset.QORA).subtract(groupApprovalTransactionData.getFee()));

		// Update admin's reference
		admin.setLastReference(groupApprovalTransactionData.getSignature());
	}

	@Override
	public void orphan() throws DataException {
		// Revert?

		// Delete this transaction itself
		this.repository.getTransactionRepository().delete(groupApprovalTransactionData);

		// Update admin's balance
		Account admin = getAdmin();
		admin.setConfirmedBalance(Asset.QORA, admin.getConfirmedBalance(Asset.QORA).add(groupApprovalTransactionData.getFee()));

		// Update admin's reference
		admin.setLastReference(groupApprovalTransactionData.getReference());
	}

}