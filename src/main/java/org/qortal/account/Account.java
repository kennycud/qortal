package org.qortal.account;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.qortal.api.resource.TransactionsResource;
import org.qortal.block.BlockChain;
import org.qortal.controller.LiteNode;
import org.qortal.data.account.AccountBalanceData;
import org.qortal.data.account.AccountData;
import org.qortal.data.account.RewardShareData;
import org.qortal.data.naming.NameData;
import org.qortal.data.transaction.TransactionData;
import org.qortal.repository.DataException;
import org.qortal.repository.GroupRepository;
import org.qortal.repository.NameRepository;
import org.qortal.repository.Repository;
import org.qortal.settings.Settings;
import org.qortal.utils.Base58;
import org.qortal.utils.Groups;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.qortal.utils.Amounts.prettyAmount;

@XmlAccessorType(XmlAccessType.NONE) // Stops JAX-RS errors when unmarshalling blockchain config
public class Account {

	private static final Logger LOGGER = LogManager.getLogger(Account.class);

	public static final int ADDRESS_LENGTH = 25;
	public static final int FOUNDER_FLAG = 0x1;

	protected Repository repository;
	protected String address;

	protected Account() {
	}

	/** Construct Account business object using account's address */
	public Account(Repository repository, String address) {
		this.repository = repository;
		this.address = address;
	}

	// Simple getters / setters

	public String getAddress() {
		return this.address;
	}

	/**
	 * Build AccountData object using available account information.
	 * <p>
	 * For example, PublicKeyAccount might override and add public key info.
	 * 
	 * @return
	 */
	protected AccountData buildAccountData() {
		return new AccountData(this.address);
	}

	public void ensureAccount() throws DataException {
		this.repository.getAccountRepository().ensureAccount(this.buildAccountData());
	}

	// Balance manipulations - assetId is 0 for QORT

	public long getConfirmedBalance(long assetId) throws DataException {
		AccountBalanceData accountBalanceData;

		if (Settings.getInstance().isLite()) {
			// Lite nodes request data from peers instead of the local db
			accountBalanceData = LiteNode.getInstance().fetchAccountBalance(this.address, assetId);
		}
		else {
			// All other node types fetch from the local db
			accountBalanceData = this.repository.getAccountRepository().getBalance(this.address, assetId);
		}

		if (accountBalanceData == null)
			return 0;

		return accountBalanceData.getBalance();
	}

	public void setConfirmedBalance(long assetId, long balance) throws DataException {
		// Safety feature!
		if (balance < 0) {
			String message = String.format("Refusing to set negative balance %s [assetId %d] for %s", prettyAmount(balance), assetId, this.address);
			LOGGER.error(message);
			throw new DataException(message);
		}

		// Delete account balance record instead of setting balance to zero
		if (balance == 0) {
			this.repository.getAccountRepository().delete(this.address, assetId);
			return;
		}

		// Can't have a balance without an account - make sure it exists!
		this.ensureAccount();

		AccountBalanceData accountBalanceData = new AccountBalanceData(this.address, assetId, balance);
		this.repository.getAccountRepository().save(accountBalanceData);

		LOGGER.trace(() -> String.format("%s balance now %s [assetId %s]", this.address, prettyAmount(balance), assetId));
	}

	// Convenience method
	public void modifyAssetBalance(long assetId, long deltaBalance) throws DataException {
		this.repository.getAccountRepository().modifyAssetBalance(this.getAddress(), assetId, deltaBalance);

		LOGGER.trace(() -> String.format("%s balance %s by %s [assetId %s]",
				this.address,
				(deltaBalance >= 0 ? "increased" : "decreased"),
				prettyAmount(Math.abs(deltaBalance)),
				assetId));
	}

	public void deleteBalance(long assetId) throws DataException {
		this.repository.getAccountRepository().delete(this.address, assetId);
	}

	// Reference manipulations

	/**
	 * Fetch last reference for account.
	 * 
	 * @return byte[] reference, or null if no reference or account not found.
	 * @throws DataException
	 */
	public byte[] getLastReference() throws DataException {
		byte[] reference = AccountRefCache.getLastReference(this.repository, this.address);
		LOGGER.trace(() -> String.format("Last reference for %s is %s", this.address, reference == null ? "null" : Base58.encode(reference)));
		return reference;
	}

	/**
	 * Set last reference for account.
	 * 
	 * @param reference
	 *            -- null allowed
	 * @throws DataException
	 */
	public void setLastReference(byte[] reference) throws DataException {
		LOGGER.trace(() -> String.format("Setting last reference for %s to %s", this.address, (reference == null ? "null" : Base58.encode(reference))));

		AccountData accountData = this.buildAccountData();
		accountData.setReference(reference);
		AccountRefCache.setLastReference(this.repository, accountData);
	}

	// Default groupID manipulations

	/** Returns account's default groupID or null if account doesn't exist. */
	public Integer getDefaultGroupId() throws DataException {
		return this.repository.getAccountRepository().getDefaultGroupId(this.address);
	}

	/**
	 * Sets account's default groupID and saves into repository.
	 * <p>
	 * Caller will need to call <tt>repository.saveChanges()</tt>.
	 * 
	 * @param defaultGroupId
	 * @throws DataException
	 */
	public void setDefaultGroupId(int defaultGroupId) throws DataException {
		AccountData accountData = this.buildAccountData();
		accountData.setDefaultGroupId(defaultGroupId);
		this.repository.getAccountRepository().setDefaultGroupId(accountData);

		LOGGER.trace(() -> String.format("Account %s defaultGroupId now %d", accountData.getAddress(), defaultGroupId));
	}

	// Account flags

	public Integer getFlags() throws DataException {
		return this.repository.getAccountRepository().getFlags(this.address);
	}

	public void setFlags(int flags) throws DataException {
		AccountData accountData = this.buildAccountData();
		accountData.setFlags(flags);
		this.repository.getAccountRepository().setFlags(accountData);
	}

	public static boolean isFounder(Integer flags) {
		return flags != null && (flags & FOUNDER_FLAG) != 0;
	}

	public boolean isFounder() throws DataException  {
		Integer flags = this.getFlags();
		return Account.isFounder(flags);
	}

	// Minting blocks

	/** Returns whether account can be considered a "minting account".
	 * <p>
	 * To be considered a "minting account", the account needs to pass some of these tests:<br>
	 * <ul>
	 * <li>account's level is at least <tt>minAccountLevelToMint</tt> from blockchain config</li>
	 * <li>account's address has registered a name</li>
	 * <li>account's address is a member of the minter group</li>
	 * </ul>
	 *
	 * @param isGroupValidated true if this account has already been validated for MINTER Group membership
	 * @return true if account can be considered "minting account"
	 * @throws DataException
	 */
	public boolean canMint(boolean isGroupValidated) throws DataException {
		AccountData accountData = this.repository.getAccountRepository().getAccount(this.address);
		NameRepository nameRepository = this.repository.getNameRepository();
		GroupRepository groupRepository = this.repository.getGroupRepository();
		String myAddress = accountData.getAddress();

		int blockchainHeight = this.repository.getBlockRepository().getBlockchainHeight();

		int levelToMint;

		if( blockchainHeight >= BlockChain.getInstance().getIgnoreLevelForRewardShareHeight() ) {
			levelToMint = 0;
		}
		else {
			levelToMint = BlockChain.getInstance().getMinAccountLevelToMint();
		}

		int level = accountData.getLevel();
		List<Integer> groupIdsToMint = Groups.getGroupIdsToMint( BlockChain.getInstance(), blockchainHeight );
		int nameCheckHeight = BlockChain.getInstance().getOnlyMintWithNameHeight();
		int groupCheckHeight = BlockChain.getInstance().getGroupMemberCheckHeight();
		int removeNameCheckHeight = BlockChain.getInstance().getRemoveOnlyMintWithNameHeight();

		// Can only mint if:
		// Account's level is at least minAccountLevelToMint from blockchain config
		if (blockchainHeight < nameCheckHeight) {
			if (Account.isFounder(accountData.getFlags())) {
				return accountData.getBlocksMintedPenalty() == 0;
			} else {
				return level >= levelToMint;
			}
		}

		// Can only mint on onlyMintWithNameHeight from blockchain config if:
		// Account's level is at least minAccountLevelToMint from blockchain config
		// Account's address has registered a name
		if (blockchainHeight >= nameCheckHeight && blockchainHeight < groupCheckHeight) {
			List<NameData> myName = nameRepository.getNamesByOwner(myAddress);
			if (Account.isFounder(accountData.getFlags())) {
				return accountData.getBlocksMintedPenalty() == 0 && !myName.isEmpty();
			} else {
				return level >= levelToMint && !myName.isEmpty();
			}
		}

		// Can only mint on groupMemberCheckHeight from blockchain config if:
		// Account's level is at least minAccountLevelToMint from blockchain config
		// Account's address has registered a name
		// Account's address is a member of the minter group
		if (blockchainHeight >= groupCheckHeight && blockchainHeight < removeNameCheckHeight) {
			List<NameData> myName = nameRepository.getNamesByOwner(myAddress);
			if (Account.isFounder(accountData.getFlags())) {
				return accountData.getBlocksMintedPenalty() == 0 && !myName.isEmpty() && (isGroupValidated || Groups.memberExistsInAnyGroup(groupRepository, groupIdsToMint, myAddress));
			} else {
				return level >= levelToMint && !myName.isEmpty() && (isGroupValidated || Groups.memberExistsInAnyGroup(groupRepository, groupIdsToMint, myAddress));
			}
		}

		// Can only mint on removeOnlyMintWithNameHeight from blockchain config if:
		// Account's level is at least minAccountLevelToMint from blockchain config
		// Account's address is a member of the minter group
		if (blockchainHeight >= removeNameCheckHeight) {
			if (Account.isFounder(accountData.getFlags())) {
				return accountData.getBlocksMintedPenalty() == 0 && (isGroupValidated || Groups.memberExistsInAnyGroup(groupRepository, groupIdsToMint, myAddress));
			} else {
				return level >= levelToMint && (isGroupValidated || Groups.memberExistsInAnyGroup(groupRepository, groupIdsToMint, myAddress));
			}
		}

		return false;
	}

	/** Returns account's blockMinted (0+) or null if account not found in repository. */
	public Integer getBlocksMinted() throws DataException {
		return this.repository.getAccountRepository().getMintedBlockCount(this.address);
	}

	/** Returns account's blockMintedPenalty or null if account not found in repository. */
	public Integer getBlocksMintedPenalty() throws DataException {
		return this.repository.getAccountRepository().getBlocksMintedPenaltyCount(this.address);
	}

	/** Returns whether account can build reward-shares.
	 * <p>
	 * To be able to create reward-shares, the account needs to pass at least one of these tests:<br>
	 * <ul>
	 * <li>account's level is at least <tt>minAccountLevelToRewardShare</tt> from blockchain config</li>
	 * <li>account has 'founder' flag set</li>
	 * </ul>
	 * 
	 * @return true if account can be considered "minting account"
	 * @throws DataException
	 */
	public boolean canRewardShare() throws DataException {
		AccountData accountData = this.repository.getAccountRepository().getAccount(this.address);

		if (accountData == null)
			return false;

		Integer level = accountData.getLevel();
		if (level != null && level >= BlockChain.getInstance().getMinAccountLevelToRewardShare())
			return true;

		if (Account.isFounder(accountData.getFlags()) && accountData.getBlocksMintedPenalty() == 0)
			return true;

		if( this.repository.getBlockRepository().getBlockchainHeight() >= BlockChain.getInstance().getIgnoreLevelForRewardShareHeight() )
			return true;

		return false;
	}

	// Account level

	/** Returns account's level (0+) or null if account not found in repository. */
	public Integer getLevel() throws DataException {
		return this.repository.getAccountRepository().getLevel(this.address);
	}

	public void setLevel(int level) throws DataException {
		AccountData accountData = this.buildAccountData();
		accountData.setLevel(level);
		this.repository.getAccountRepository().setLevel(accountData);
	}

	public void setBlocksMintedAdjustment(int blocksMintedAdjustment) throws DataException {
		AccountData accountData = this.buildAccountData();
		accountData.setBlocksMintedAdjustment(blocksMintedAdjustment);
		this.repository.getAccountRepository().setBlocksMintedAdjustment(accountData);
	}

	/**
	 * Returns 'effective' minting level, or zero if account does not exist/cannot mint.
	 * <p>
	 * For founder accounts with no penalty, this returns "founderEffectiveMintingLevel" from blockchain config.
	 * 
	 * @return 0+
	 * @throws DataException
	 */
	public int getEffectiveMintingLevel() throws DataException {
		AccountData accountData = this.repository.getAccountRepository().getAccount(this.address);
		if (accountData == null)
			return 0;

		// Founders are assigned a different effective minting level, as long as they have no penalty
		if (Account.isFounder(accountData.getFlags()) && accountData.getBlocksMintedPenalty() == 0)
			return BlockChain.getInstance().getFounderEffectiveMintingLevel();

		return accountData.getLevel();
	}

	/**
	 * Get Primary Name
	 *
	 * @return the primary name for this address if present, otherwise empty
	 *
	 * @throws DataException
	 */
	public Optional<String> getPrimaryName() throws DataException {

		return this.repository.getNameRepository().getPrimaryName(this.address);
	}

	/**
	 * Remove Primary Name
	 *
	 * @throws DataException
	 */
	public void removePrimaryName() throws DataException {
		this.repository.getNameRepository().removePrimaryName(this.address);
	}

	/**
	 * Reset Primary Name
	 *
	 * Set primary name based on the names (and their history) this account owns.
	 *
	 * @param confirmationStatus the status of the transactions for the determining the primary name
	 *
	 * @return the primary name, empty if their isn't one
	 *
	 * @throws DataException
	 */
	public Optional<String> resetPrimaryName(TransactionsResource.ConfirmationStatus confirmationStatus) throws DataException {
		Optional<String> primaryName = determinePrimaryName(confirmationStatus);

		if(primaryName.isPresent()) {
			return setPrimaryName(primaryName.get());
		}
		else {
			return primaryName;
		}
	}

	/**
	 * Determine Primary Name
	 *
	 * Determine primary name based on a list of registered names.
	 *
	 * @param confirmationStatus the status of the transactions for this determination
	 *
	 * @return the primary name, empty if there is no primary name
	 *
	 * @throws DataException
	 */
	public Optional<String> determinePrimaryName(TransactionsResource.ConfirmationStatus confirmationStatus) throws DataException {

		// all registered names for the owner
		List<NameData> names = this.repository.getNameRepository().getNamesByOwner(this.address);

		Optional<String> primaryName;

		// if no registered names, the no primary name possible
		if (names.isEmpty()) {
			primaryName = Optional.empty();
		}
		// if names
		else {
			// if one name, then that is the primary name
			if (names.size() == 1) {
				primaryName = Optional.of( names.get(0).getName() );
			}
			// if more than one name, then seek the earliest name acquisition that was never released
			else {
				Map<String, TransactionData> txByName = new HashMap<>(names.size());

				// for each name, get the latest transaction
				for (NameData nameData : names) {

					// since the name is currently registered to the owner,
					// we assume the latest transaction involving this name was the transaction that the acquired
					// name through registration, purchase or update
					Optional<TransactionData> latestTransaction
							= this.repository
							.getTransactionRepository()
							.getTransactionsInvolvingName(
									nameData.getName(),
									confirmationStatus
							)
							.stream()
							.sorted(Comparator.comparing(
									TransactionData::getTimestamp).reversed()
							)
							.findFirst(); // first is the last, since it was reversed

					// if there is a latest transaction, expected for all registered names
					if (latestTransaction.isPresent()) {
						txByName.put(nameData.getName(), latestTransaction.get());
					}
					// if there is no latest transaction, then
					else {
						LOGGER.warn("No matching transaction for name: " + nameData.getName());
					}
				}

				// get the first name aqcuistion for this address
				Optional<Map.Entry<String, TransactionData>> firstNameEntry
						= txByName.entrySet().stream().sorted(Comparator.comparing(entry -> entry.getValue().getTimestamp())).findFirst();

				// if their is a name acquisition, then the first one is the primary name
				if (firstNameEntry.isPresent()) {
					primaryName = Optional.of( firstNameEntry.get().getKey() );
				}
				// if there is no nameacquistion, then there is no primary name
				else {
					primaryName =  Optional.empty();
				}
			}
		}
		return primaryName;
	}

	/**
	 * Set Primary Name
	 *
	 * @param primaryName the primary to set to this address
	 *
	 * @return the primary name if successful, empty if unsuccessful
	 *
	 * @throws DataException
	 */
	public Optional<String> setPrimaryName( String primaryName ) throws DataException {
		int changed = this.repository.getNameRepository().setPrimaryName(this.address, primaryName);

		return changed > 0 ? Optional.of(primaryName) : Optional.empty();
	}

	/**
	 * Returns reward-share minting address, or unknown if reward-share does not exist.
	 * 
	 * @param repository
	 * @param rewardSharePublicKey
	 * @return address or unknown
	 * @throws DataException
	 */
	public static String getRewardShareMintingAddress(Repository repository, byte[] rewardSharePublicKey) throws DataException {
		// Find actual minter address
		RewardShareData rewardShareData = repository.getAccountRepository().getRewardShare(rewardSharePublicKey);

		if (rewardShareData == null)
			return "Unknown";

		return rewardShareData.getMinter();
	}

	/**
	 * Returns 'effective' minting level, or zero if reward-share does not exist.
	 *
	 * @param repository
	 * @param rewardSharePublicKey
	 * @return 0+
	 * @throws DataException
	 */
	public static int getRewardShareEffectiveMintingLevel(Repository repository, byte[] rewardSharePublicKey) throws DataException {
		// Find actual minter and get their effective minting level
		RewardShareData rewardShareData = repository.getAccountRepository().getRewardShare(rewardSharePublicKey);
		if (rewardShareData == null)
			return 0;

		Account rewardShareMinter = new Account(repository, rewardShareData.getMinter());
		return rewardShareMinter.getEffectiveMintingLevel();
	}

	/**
	 * Returns 'effective' minting level, with a fix for the zero level.
	 * <p>
	 * For founder accounts with no penalty, this returns "founderEffectiveMintingLevel" from blockchain config.
	 *
	 * @param repository
	 * @param rewardSharePublicKey
	 * @return 0+
	 * @throws DataException
	 */
	public static int getRewardShareEffectiveMintingLevelIncludingLevelZero(Repository repository, byte[] rewardSharePublicKey) throws DataException {
		// Find actual minter and get their effective minting level
		RewardShareData rewardShareData = repository.getAccountRepository().getRewardShare(rewardSharePublicKey);
		if (rewardShareData == null)
			return 0;

		else if (!rewardShareData.getMinter().equals(rewardShareData.getRecipient())) // Sponsorship reward share
			return 0;

		Account rewardShareMinter = new Account(repository, rewardShareData.getMinter());
		return rewardShareMinter.getEffectiveMintingLevel();
	}
}
