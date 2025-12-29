package org.qortal.controller;

import com.rust.litewalletjni.LiteWalletJni;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;
import org.qortal.arbitrary.ArbitraryDataFile;
import org.qortal.arbitrary.ArbitraryDataReader;
import org.qortal.arbitrary.ArbitraryDataResource;
import org.qortal.arbitrary.exception.MissingDataException;
import org.qortal.crosschain.ForeignBlockchainException;
import org.qortal.crosschain.PirateWallet;
import org.qortal.data.arbitrary.ArbitraryResourceStatus;
import org.qortal.data.transaction.ArbitraryTransactionData;
import org.qortal.data.transaction.TransactionData;
import org.qortal.network.Network;
import org.qortal.network.Peer;
import org.qortal.repository.DataException;
import org.qortal.repository.Repository;
import org.qortal.repository.RepositoryManager;
import org.qortal.settings.Settings;
import org.qortal.transaction.ArbitraryTransaction;
import org.qortal.utils.ArbitraryTransactionUtils;
import org.qortal.utils.Base58;
import org.qortal.utils.FilesystemUtils;
import org.qortal.utils.NTP;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public class PirateChainWalletController extends Thread {

    protected static final Logger LOGGER = LogManager.getLogger(PirateChainWalletController.class);

    private static PirateChainWalletController instance;

    final private static long SAVE_INTERVAL = 60 * 60 * 1000L; // 1 hour
    private long lastSaveTime = 0L;

    private boolean running;
    private PirateWallet currentWallet = null;
    private boolean shouldLoadWallet = false;
    private String loadStatus = null;

    private static final long WALLET_LOCK_TIMEOUT_MS = 5_000L;
    private static final long SWITCH_LOCK_TIMEOUT_MS = 30_000L;
    private static final long SYNC_STOP_TIMEOUT_MS = 30_000L;
    private static final long SYNC_WAIT_INTERVAL_MS = 250L;
    private static final long STATUS_LOCK_TIMEOUT_MS = 500L;
    private static final String NULL_SEED_ENTROPY58 = Base58.encode(new byte[32]);

    private final ReentrantLock walletLock = new ReentrantLock(true);
    private final Object syncMonitor = new Object();
    private final Object switchingMonitor = new Object();
    private volatile boolean syncInProgress = false;
    private volatile Thread switchingThread = null;
    private int switchingDepth = 0;
    private final ThreadLocal<Integer> switchingClaims = ThreadLocal.withInitial(() -> 0);

    private static String qdnWalletSignature = "4DtYWqBSsPaeY8u42zpWQuxogN1N9USbYFuidgaXfxNv5gneNtkVXSd7Lani7dGq7WpTZZzPfBcBhG349FXbQiUn";

    private PirateChainWalletController() {
        this.running = true;
    }

    public static PirateChainWalletController getInstance() {
        if (instance == null)
            instance = new PirateChainWalletController();

        return instance;
    }

    private boolean isSwitching() {
        synchronized (this.switchingMonitor) {
            return this.switchingThread != null;
        }
    }

    private boolean isSwitchingByCurrentThread() {
        synchronized (this.switchingMonitor) {
            return Thread.currentThread() == this.switchingThread;
        }
    }

    private boolean claimSwitching() {
        synchronized (this.switchingMonitor) {
            if (this.switchingThread == null) {
                this.switchingThread = Thread.currentThread();
                this.switchingDepth = 1;
            } else if (this.switchingThread == Thread.currentThread()) {
                this.switchingDepth++;
            } else {
                return false;
            }
        }
        this.switchingClaims.set(this.switchingClaims.get() + 1);
        return true;
    }

    private void releaseSwitchingClaim() {
        int claims = this.switchingClaims.get();
        if (claims > 0) {
            this.switchingClaims.set(claims - 1);
            synchronized (this.switchingMonitor) {
                if (this.switchingThread == Thread.currentThread()) {
                    this.switchingDepth--;
                    if (this.switchingDepth <= 0) {
                        this.switchingDepth = 0;
                        this.switchingThread = null;
                    }
                }
            }
        }
    }

    private boolean acquireWalletLock(long timeoutMs) {
        try {
            return this.walletLock.tryLock(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private void releaseWalletLockIfHeld() {
        if (this.walletLock.isHeldByCurrentThread()) {
            this.walletLock.unlock();
        }
    }

    private boolean waitForSyncIdle(long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        synchronized (this.syncMonitor) {
            while (this.syncInProgress) {
                long remaining = deadline - System.currentTimeMillis();
                if (remaining <= 0) {
                    return false;
                }
                long waitTime = Math.min(remaining, SYNC_WAIT_INTERVAL_MS);
                try {
                    this.syncMonitor.wait(waitTime);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
        return true;
    }

    private void stopSyncIfRunning(long timeoutMs) {
        if (!this.syncInProgress) {
            return;
        }

        try {
            LiteWalletJni.execute("stop", "");
        } catch (RuntimeException e) {
            LOGGER.debug("Unable to stop Pirate Chain sync: {}", e.getMessage());
        }

        if (!this.waitForSyncIdle(timeoutMs)) {
            LOGGER.info("Timed out waiting for Pirate Chain sync to stop");
        }
    }

    private boolean needsWalletSwitch(byte[] entropyBytes, boolean isNullSeedWallet) {
        if (this.currentWallet == null) {
            return true;
        }
        if (!this.currentWallet.entropyBytesEqual(entropyBytes)) {
            return true;
        }
        return this.currentWallet.isNullSeedWallet() != isNullSeedWallet;
    }

    @Override
    public void run() {
        Thread.currentThread().setName("Pirate Chain Wallet Controller");
        Thread.currentThread().setPriority(MIN_PRIORITY);

        try {
            while (running && !Controller.isStopping()) {
                Thread.sleep(1000);

                // Wait until we have a request to load the wallet
                if (!shouldLoadWallet) {
                    continue;
                }

                if (!LiteWalletJni.isLoaded()) {
                    this.loadLibrary();

                    // If still not loaded, sleep to prevent too many requests
                    if (!LiteWalletJni.isLoaded()) {
                        Thread.sleep(5 * 1000);
                        continue;
                    }
                }

                // Wallet is downloaded, so clear the status
                this.loadStatus = null;

                PirateWallet wallet = this.currentWallet;
                if (wallet == null) {
                    // Nothing to do yet
                    continue;
                }
                if (wallet.isNullSeedWallet()) {
                    // Don't sync the null seed wallet
                    continue;
                }

                if (this.isSwitching()) {
                    continue;
                }

                if (!this.acquireWalletLock(0)) {
                    continue;
                }

                boolean syncStarted = false;
                try {
                    if (this.isSwitching()) {
                        continue;
                    }

                    synchronized (this.syncMonitor) {
                        this.syncInProgress = true;
                    }
                    syncStarted = true;

                    LOGGER.debug("Syncing Pirate Chain wallet...");
                    String response = LiteWalletJni.execute("sync", "");
                    LOGGER.debug("sync response: {}", response);

                    try {
                        JSONObject json = new JSONObject(response);
                        if (json.has("result")) {
                            String result = json.getString("result");

                            // We may have to set wallet to ready if this is the first ever successful sync
                            if (Objects.equals(result, "success")) {
                                this.currentWallet.setReady(true);
                            }
                        }
                    } catch (JSONException e) {
                        LOGGER.info("Unable to interpret JSON", e);
                    }
                } finally {
                    if (syncStarted) {
                        synchronized (this.syncMonitor) {
                            this.syncInProgress = false;
                            this.syncMonitor.notifyAll();
                        }
                    }
                    this.releaseWalletLockIfHeld();
                }

                // Rate limit sync attempts
                Thread.sleep(30000);

                // Save wallet if needed
                Long now = NTP.getTime();
                if (now != null && now - SAVE_INTERVAL >= this.lastSaveTime) {
                    this.saveCurrentWallet();
                }
            }
        } catch (InterruptedException e) {
            // Fall-through to exit
        }
    }

    public void shutdown() {
        // Save the wallet
        this.saveCurrentWallet();

        this.running = false;
        this.interrupt();
    }

    // QDN & wallet libraries

    private void loadLibrary() throws InterruptedException {
        try (final Repository repository = RepositoryManager.getRepository()) {

            // Check if architecture is supported
            String libFileName = PirateChainWalletController.getRustLibFilename();
            if (libFileName == null) {
                String osName = System.getProperty("os.name");
                String osArchitecture = System.getProperty("os.arch");
                this.loadStatus = String.format("Unsupported architecture (%s %s)", osName, osArchitecture);
                return;
            }

            // Check if the library exists in the wallets folder
            Path libDirectory = PirateChainWalletController.getRustLibOuterDirectory();
            Path libPath = Paths.get(libDirectory.toString(), libFileName);
            if (Files.exists(libPath)) {
                // Already downloaded; we can load the library right away
                LiteWalletJni.loadLibrary();
                return;
            }

            // Library not found, so check if we've fetched the resource from QDN
            ArbitraryTransactionData t = this.getTransactionData(repository);
            if (t == null || t.getService() == null) {
                // Can't find the transaction - maybe on a different chain?
                return;
            }

            // Wait until we have a sufficient number of peers to attempt QDN downloads
            List<Peer> handshakedPeers = Network.getInstance().getImmutableHandshakedPeers();
            if (handshakedPeers.size() < Settings.getInstance().getMinBlockchainPeers()) {
                // Wait for more peers
                this.loadStatus = String.format("Searching for peers...");
                return;
            }

            // Build resource
            ArbitraryDataReader arbitraryDataReader = new ArbitraryDataReader(t.getName(),
                    ArbitraryDataFile.ResourceIdType.NAME, t.getService(), t.getIdentifier());
            try {
                arbitraryDataReader.loadSynchronously(false);
            } catch (MissingDataException e) {
                LOGGER.info("Missing data when loading Pirate Chain library");
            }

            // Check its status
            ArbitraryResourceStatus status = ArbitraryTransactionUtils.getStatus(
                    t.getService(), t.getName(), t.getIdentifier(), false, true);

            if (status.getStatus() != ArbitraryResourceStatus.Status.READY) {
                LOGGER.info("Not ready yet: {}", status.getTitle());
                this.loadStatus = String.format("Downloading files from QDN... (%d / %d)", status.getLocalChunkCount(),
                        status.getTotalChunkCount());
                return;
            }

            // Files are downloaded, so copy the necessary files to the wallets folder
            // Delete the wallets/*/lib directory first, in case earlier versions of the
            // wallet are present
            Path walletsLibDirectory = PirateChainWalletController.getWalletsLibDirectory();
            if (Files.exists(walletsLibDirectory)) {
                FilesystemUtils.safeDeleteDirectory(walletsLibDirectory, false);
            }
            Files.createDirectories(libDirectory);
            FileUtils.copyDirectory(arbitraryDataReader.getFilePath().toFile(), libDirectory.toFile());

            // Clear reader cache so only one copy exists
            ArbitraryDataResource resource = new ArbitraryDataResource(t.getName(),
                    ArbitraryDataFile.ResourceIdType.NAME, t.getService(), t.getIdentifier());
            resource.deleteCache();

            // Finally, load the library
            LiteWalletJni.loadLibrary();

        } catch (DataException e) {
            LOGGER.error("Repository issue when loading Pirate Chain library", e);
        } catch (IOException e) {
            LOGGER.error("Error when loading Pirate Chain library", e);
        }
    }

    private ArbitraryTransactionData getTransactionData(Repository repository) {
        try {
            byte[] signature = Base58.decode(qdnWalletSignature);
            TransactionData transactionData = repository.getTransactionRepository().fromSignature(signature);
            if (!(transactionData instanceof ArbitraryTransactionData))
                return null;

            ArbitraryTransaction arbitraryTransaction = new ArbitraryTransaction(repository, transactionData);
            if (arbitraryTransaction != null) {
                return (ArbitraryTransactionData) arbitraryTransaction.getTransactionData();
            }

            return null;
        } catch (DataException e) {
            return null;
        }
    }

    public static String getRustLibFilename() {
        String osName = System.getProperty("os.name");
        String osArchitecture = System.getProperty("os.arch");

        if (osName.equals("Mac OS X") && osArchitecture.equals("x86_64")) {
            return "librust-macos-x86_64.dylib";
        } else if (osName.equals("Mac OS X") && osArchitecture.equals("aarch64")) {
            return "librust-macos-aarch64.dylib";
        } else if ((osName.equals("Linux") || osName.equals("FreeBSD")) && osArchitecture.equals("aarch64")) {
            return "librust-linux-aarch64.so";
        } else if ((osName.equals("Linux") || osName.equals("FreeBSD")) && osArchitecture.equals("amd64")) {
            return "librust-linux-x86_64.so";
        } else if (osName.contains("Windows") && osArchitecture.equals("amd64")) {
            return "librust-windows-x86_64.dll";
        }

        return null;
    }

    public static Path getWalletsLibDirectory() {
        return Paths.get(Settings.getInstance().getWalletsPath(), "PirateChain", "lib");
    }

    public static Path getRustLibOuterDirectory() {
        String sigPrefix = qdnWalletSignature.substring(0, 8);
        return Paths.get(Settings.getInstance().getWalletsPath(), "PirateChain", "lib", sigPrefix);
    }

    // Wallet functions

    public boolean initWithEntropy58(String entropy58) {
        return this.initWithEntropy58(entropy58, false);
    }

    public boolean initNullSeedWallet() {
        return this.initWithEntropy58(NULL_SEED_ENTROPY58, true);
    }

    private boolean initWithEntropy58(String entropy58, boolean isNullSeedWallet) {
        try {
            this.beginWalletUse(entropy58, isNullSeedWallet, false, false);
            return true;
        } catch (ForeignBlockchainException e) {
            return false;
        } finally {
            this.endWalletUse();
        }
    }

    public void beginWalletUse(String entropy58, boolean isNullSeedWallet, boolean requireSync,
            boolean requireNotNullSeed)
            throws ForeignBlockchainException {
        // If the JNI library isn't loaded yet then we can't proceed
        if (!LiteWalletJni.isLoaded()) {
            this.shouldLoadWallet = true;
            throw new ForeignBlockchainException("Pirate wallet isn't initialized yet");
        }

        if (entropy58 == null) {
            throw new ForeignBlockchainException("Invalid entropy bytes");
        }

        byte[] entropyBytes = Base58.decode(entropy58);
        if (entropyBytes == null || entropyBytes.length != 32) {
            throw new ForeignBlockchainException("Invalid entropy bytes");
        }

        boolean needsSwitch = this.needsWalletSwitch(entropyBytes, isNullSeedWallet);
        boolean claimedSwitching = false;
        if (!needsSwitch && this.isSwitching() && !this.isSwitchingByCurrentThread()) {
            throw new ForeignBlockchainException("Wallet switch in progress");
        }
        if (needsSwitch) {
            claimedSwitching = this.claimSwitching();
            if (!claimedSwitching) {
                throw new ForeignBlockchainException("Wallet switch in progress");
            }
            this.stopSyncIfRunning(SYNC_STOP_TIMEOUT_MS);
        } else if (this.isSwitchingByCurrentThread()) {
            claimedSwitching = this.claimSwitching();
        }

        long timeoutMs = needsSwitch ? SWITCH_LOCK_TIMEOUT_MS : WALLET_LOCK_TIMEOUT_MS;
        if (!this.acquireWalletLock(timeoutMs)) {
            if (claimedSwitching) {
                this.releaseSwitchingClaim();
            }
            if (this.syncInProgress) {
                throw new ForeignBlockchainException("Sync in progress. Please try again later.");
            }
            if (this.isSwitching()) {
                throw new ForeignBlockchainException("Wallet switch in progress");
            }
            throw new ForeignBlockchainException("Wallet busy. Please try again later.");
        }

        try {
            boolean needsSwitchLocked = this.needsWalletSwitch(entropyBytes, isNullSeedWallet);
            if (needsSwitchLocked) {
                this.closeCurrentWallet();
                this.currentWallet = new PirateWallet(entropyBytes, isNullSeedWallet);
                if (!this.currentWallet.isReady()) {
                    this.currentWallet = null;
                    throw new ForeignBlockchainException("Pirate wallet isn't initialized yet");
                }
            }

            this.ensureInitialized();
            if (requireNotNullSeed) {
                this.ensureNotNullSeed();
            }
            if (requireSync) {
                this.ensureSynchronized();
            }
        } catch (ForeignBlockchainException e) {
            this.releaseWalletLockIfHeld();
            if (claimedSwitching) {
                this.releaseSwitchingClaim();
            }
            throw e;
        } catch (IOException e) {
            this.releaseWalletLockIfHeld();
            if (claimedSwitching) {
                this.releaseSwitchingClaim();
            }
            throw new ForeignBlockchainException("Unable to initialize wallet: " + e.getMessage());
        } catch (RuntimeException e) {
            this.releaseWalletLockIfHeld();
            if (claimedSwitching) {
                this.releaseSwitchingClaim();
            }
            throw e;
        }
    }

    public void beginNullSeedWalletUse(boolean requireSync) throws ForeignBlockchainException {
        this.beginWalletUse(NULL_SEED_ENTROPY58, true, requireSync, false);
    }

    public void endWalletUse() {
        this.releaseWalletLockIfHeld();
        this.releaseSwitchingClaim();
    }

    private void saveCurrentWallet() {
        if (this.currentWallet == null) {
            // Nothing to do
            return;
        }
        boolean lockedHere = false;
        if (!this.walletLock.isHeldByCurrentThread()) {
            lockedHere = this.acquireWalletLock(WALLET_LOCK_TIMEOUT_MS);
            if (!lockedHere) {
                return;
            }
        }
        try {
            if (this.currentWallet == null) {
                return;
            }
            if (this.currentWallet.save()) {
                Long now = NTP.getTime();
                if (now != null) {
                    this.lastSaveTime = now;
                }
            }
        } catch (IOException e) {
            LOGGER.info("Unable to save wallet");
        } finally {
            if (lockedHere) {
                this.releaseWalletLockIfHeld();
            }
        }
    }

    public PirateWallet getCurrentWallet() {
        return this.currentWallet;
    }

    private void closeCurrentWallet() {
        this.saveCurrentWallet();
        this.currentWallet = null;
    }

    public void ensureInitialized() throws ForeignBlockchainException {
        if (!LiteWalletJni.isLoaded() || this.currentWallet == null || !this.currentWallet.isInitialized()) {
            throw new ForeignBlockchainException("Pirate wallet isn't initialized yet");
        }
    }

    public void ensureNotNullSeed() throws ForeignBlockchainException {
        // Safety check to make sure funds aren't sent to a null seed wallet
        if (this.currentWallet == null || this.currentWallet.isNullSeedWallet()) {
            throw new ForeignBlockchainException("Invalid wallet");
        }
    }

    public void ensureSynchronized() throws ForeignBlockchainException {
        if (this.isSwitching() && !this.isSwitchingByCurrentThread()) {
            throw new ForeignBlockchainException("Wallet switch in progress");
        }
        if (this.syncInProgress) {
            throw new ForeignBlockchainException("Sync in progress. Please try again later.");
        }
        if (!this.walletLock.isHeldByCurrentThread()) {
            throw new ForeignBlockchainException("Wallet busy. Please try again later.");
        }
        if (this.currentWallet == null || !this.currentWallet.isSynchronized()) {
            throw new ForeignBlockchainException("Wallet isn't synchronized yet");
        }

        String response = LiteWalletJni.execute("syncStatus", "");
        JSONObject json = new JSONObject(response);
        boolean inProgress = json.optBoolean("in_progress", false);
        if (inProgress) {
            String progress = this.formatSyncProgress(json);
            String progressSuffix = progress != null ? String.format(" (%s)", progress) : "";
            throw new ForeignBlockchainException(
                    String.format("Sync in progress%s. Please try again later.", progressSuffix));
        }
    }

    private Long fetchChainHeight() {
        String response = LiteWalletJni.execute("info", "");
        try {
            JSONObject json = new JSONObject(response);
            if (json.has("latest_block_height")) {
                return json.getLong("latest_block_height");
            }
        } catch (JSONException e) {
            // Fall through to return null.
        }
        return null;
    }

    private String formatSyncProgress(JSONObject statusJson) {
        long syncedBlocks = statusJson.optLong("synced_blocks", -1);
        long endBlock = statusJson.optLong("end_block", -1);
        long startBlock = statusJson.optLong("start_block", -1);

        if (endBlock > 0 && syncedBlocks >= 0) {
            long currentHeight = endBlock - 1 + syncedBlocks;
            if (startBlock > 0 && currentHeight > startBlock) {
                currentHeight = startBlock;
            }

            Long chainHeight = this.fetchChainHeight();
            if (chainHeight != null && chainHeight >= 0) {
                if (currentHeight > chainHeight) {
                    currentHeight = chainHeight;
                }
                return String.format("%d / %d", currentHeight, chainHeight);
            }
        }

        long totalBlocks = statusJson.optLong("total_blocks", -1);
        if (syncedBlocks >= 0 && totalBlocks >= 0) {
            return String.format("%d / %d", syncedBlocks, totalBlocks);
        }

        return null;
    }

    private String formatSyncStatus(PirateWallet wallet) {
        String syncStatusResponse = LiteWalletJni.execute("syncStatus", "");
        JSONObject json = new JSONObject(syncStatusResponse);
        boolean inProgress = json.optBoolean("in_progress", false);
        if (inProgress) {
            String progress = this.formatSyncProgress(json);
            if (progress != null) {
                return String.format("Sync in progress (%s)", progress);
            }
            return "Sync in progress";
        }

        if (wallet != null && wallet.isSynchronized()) {
            return "Synchronized";
        }

        return "Initializing wallet...";
    }

    public String getSyncStatus() {
        PirateWallet wallet = this.currentWallet;
        if (wallet == null || !wallet.isInitialized()) {
            if (this.loadStatus != null) {
                return this.loadStatus;
            }

            return "Not initialized yet";
        }

        if (this.isSwitching() && !this.isSwitchingByCurrentThread()) {
            return "Wallet switch in progress";
        }
        if (this.syncInProgress) {
            return this.formatSyncStatus(wallet);
        }

        boolean lockedHere = false;
        if (!this.walletLock.isHeldByCurrentThread()) {
            lockedHere = this.acquireWalletLock(STATUS_LOCK_TIMEOUT_MS);
            if (!lockedHere) {
                if (this.syncInProgress) {
                    return this.formatSyncStatus(wallet);
                }
                if (this.isSwitching()) {
                    return "Wallet switch in progress";
                }
                return "Wallet busy";
            }
        }

        try {
            if (this.currentWallet == null || !this.currentWallet.isInitialized()) {
                if (this.loadStatus != null) {
                    return this.loadStatus;
                }
                return "Not initialized yet";
            }

            return this.formatSyncStatus(this.currentWallet);
        } finally {
            if (lockedHere) {
                this.releaseWalletLockIfHeld();
            }
        }
    }

}
