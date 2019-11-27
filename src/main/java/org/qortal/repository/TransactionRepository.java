package org.qortal.repository;

import java.util.List;
import java.util.Map;

import org.qortal.api.resource.TransactionsResource.ConfirmationStatus;
import org.qortal.data.group.GroupApprovalData;
import org.qortal.data.transaction.GroupApprovalTransactionData;
import org.qortal.data.transaction.TransactionData;
import org.qortal.data.transaction.TransferAssetTransactionData;
import org.qortal.transaction.Transaction.TransactionType;

public interface TransactionRepository {

	// Fetching transactions / transaction height

	public TransactionData fromSignature(byte[] signature) throws DataException;

	public TransactionData fromReference(byte[] reference) throws DataException;

	public TransactionData fromHeightAndSequence(int height, int sequence) throws DataException;

	/** Returns block height containing transaction or 0 if not in a block or transaction doesn't exist */
	public int getHeightFromSignature(byte[] signature) throws DataException;

	public boolean exists(byte[] signature) throws DataException;

	// Transaction participants

	public List<byte[]> getSignaturesInvolvingAddress(String address) throws DataException;

	public void saveParticipants(TransactionData transactionData, List<String> participants) throws DataException;

	public void deleteParticipants(TransactionData transactionData) throws DataException;

	// Searching transactions

	/**
	 * Returns number of each transaction type in blocks from startHeight to endHeight inclusive.
	 * <p>
	 * Note: endHeight >= startHeight
	 * 
	 * @param startHeight height of first block to check
	 * @param endHeight height of last block to check
	 * @return transaction counts, indexed by transaction type value
	 * @throws DataException
	 */
	public Map<TransactionType, Integer> getTransactionSummary(int startHeight, int endHeight) throws DataException;

	/**
	 * Returns signatures for transactions that match search criteria.
	 * <p>
	 * If <tt>blockLimit</tt> is specified, and <tt>startBlock</tt> is <tt>null</tt>,
	 * then <tt>startBlock</tt> is assumed to be 1 or max-block-height,
	 * depending on <tt>reverse</tt> being <tt>false</tt> or <tt>true</tt>
	 * respectively.
	 * 
	 * @param startBlock height of first block to check
	 * @param blockLimit number of blocks (from <tt>startBlock</tt>) to check
	 * @param txGroupId
	 * @param txTypes
	 * @param service arbitrary transaction service ID
	 * @param address
	 * @param confirmationStatus
	 * @param limit
	 * @param offset
	 * @param reverse
	 * @return
	 * @throws DataException
	 */
	public List<byte[]> getSignaturesMatchingCriteria(Integer startBlock, Integer blockLimit, Integer txGroupId,
			List<TransactionType> txTypes, Integer service, String address,
			ConfirmationStatus confirmationStatus, Integer limit, Integer offset, Boolean reverse) throws DataException;

	/**
	 * Returns signature for latest auto-update transaction.
	 * <p>
	 * Transaction must be <tt>CONFIRMED</tt> and <tt>APPROVED</tt>
	 * and also <b>not</b> created by group admin/owner.
	 * <p>
	 * We can check the latter by testing for transaction's <tt>approvalHeight</tt>
	 * being greater than <tt>blockHeight</tt>.
	 * 
	 * @param txType
	 * @param txGroupId
	 * @param service
	 * @return
	 * @throws DataException
	 */
	public byte[] getLatestAutoUpdateTransaction(TransactionType txType, int txGroupId, Integer service) throws DataException;

	/**
	 * Returns list of transactions relating to specific asset ID.
	 * 
	 * @param assetId
	 * @param confirmationStatus
	 * @param limit
	 * @param offset
	 * @param reverse
	 * @return list of transactions, or empty if none
	 */
	public List<TransactionData> getAssetTransactions(long assetId, ConfirmationStatus confirmationStatus, Integer limit, Integer offset, Boolean reverse)
			throws DataException;

	/**
	 * Returns list of TRANSFER_ASSET transactions relating to specific asset ID, with optional address filter.
	 * 
	 * @param assetId
	 * @param address
	 * @param limit
	 * @param offset
	 * @param reverse
	 * @return list of transactions, or empty if none
	 */
	public List<TransferAssetTransactionData> getAssetTransfers(long assetId, String address, Integer limit, Integer offset, Boolean reverse)
			throws DataException;

	/**
	 * Returns list of transactions pending approval, with optional txGgroupId filtering.
	 * <p>
	 * This is typically called by the API.
	 * 
	 * @param txGroupId
	 * @param limit
	 * @param offset
	 * @param reverse
	 * @return list of transactions, or empty if none.
	 * @throws DataException
	 */
	public List<TransactionData> getApprovalPendingTransactions(Integer txGroupId, Integer limit, Integer offset, Boolean reverse) throws DataException;

	/**
	 * Returns list of transactions pending approval that can be resolved as of passed blockHeight.
	 * <p>
	 * Typically called by Block.process().
	 * 
	 * @param blockHeight
	 * @return
	 * @throws DataException
	 */
	public List<TransactionData> getApprovalPendingTransactions(int blockHeight) throws DataException;

	/**
	 * Returns list of transactions that have now expired as of passed blockHeight.
	 * <p>
	 * Typically called by Block.process().
	 * 
	 * @param blockHeight
	 * @return
	 * @throws DataException
	 */
	public List<TransactionData> getApprovalExpiringTransactions(int blockHeight) throws DataException;

	/** Returns list of transactions that had group-approval decided at passed block height. */
	public List<TransactionData> getApprovalTransactionDecidedAtHeight(int approvalHeight) throws DataException;

	/** Returns latest approval decision by given admin for given pending transaction signature. */
	public GroupApprovalTransactionData getLatestApproval(byte[] pendingSignature, byte[] adminPublicKey) throws DataException;

	/**
	 * Returns list of latest approval decisions for given pending transaction signature.
	 * 
	 * @param pendingSignature
	 * @return
	 * @throws DataException
	 */
	public GroupApprovalData getApprovalData(byte[] pendingSignature) throws DataException;

	/**
	 * Returns whether transaction is confirmed or not.
	 * 
	 * @param signature
	 * @return true if confirmed, false if not.
	 */
	public boolean isConfirmed(byte[] signature) throws DataException;

	/**
	 * Returns list of unconfirmed transaction signatures in timestamp-else-signature order.
	 * 
	 * @return list of transaction signatures, or empty if none.
	 * @throws DataException
	 */
	public List<byte[]> getUnconfirmedTransactionSignatures() throws DataException;

	/**
	 * Returns list of unconfirmed transactions in timestamp-else-signature order.
	 * <p>
	 * This is typically called by the API.
	 * 
	 * @param limit
	 * @param offset
	 * @param reverse
	 * @return list of transactions, or empty if none.
	 * @throws DataException
	 */
	public List<TransactionData> getUnconfirmedTransactions(Integer limit, Integer offset, Boolean reverse) throws DataException;

	/**
	 * Returns list of unconfirmed transactions in timestamp-else-signature order.
	 * 
	 * @return list of transactions, or empty if none.
	 * @throws DataException
	 */
	public default List<TransactionData> getUnconfirmedTransactions() throws DataException {
		return getUnconfirmedTransactions(null, null, null);
	}

	/**
	 * Remove transaction from unconfirmed transactions pile.
	 * 
	 * @param signature
	 * @throws DataException
	 */
	public void confirmTransaction(byte[] signature) throws DataException;

	public void updateBlockHeight(byte[] signature, Integer height) throws DataException;

	public void updateApprovalHeight(byte[] signature, Integer approvalHeight) throws DataException;

	/**
	 * Add transaction to unconfirmed transactions pile.
	 * 
	 * @param transactionData
	 * @throws DataException
	 */
	public void unconfirmTransaction(TransactionData transactionData) throws DataException;

	public void save(TransactionData transactionData) throws DataException;

	public void delete(TransactionData transactionData) throws DataException;

}