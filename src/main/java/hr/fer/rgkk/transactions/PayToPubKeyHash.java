package hr.fer.rgkk.transactions;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;

import static org.bitcoinj.script.ScriptOpCodes.*;

public class PayToPubKeyHash extends ScriptTransaction {

    private final ECKey ecKey;

    public PayToPubKeyHash(WalletKit walletKit, NetworkParameters parameters) {
        super(walletKit, parameters);
        ecKey = getWallet().freshReceiveKey();
    }

    @Override
    public Script createLockingScript() {
        return new ScriptBuilder()
                .op(OP_DUP)
                .op(OP_HASH160)
                .data(ecKey.getPubKeyHash())
                .op(OP_EQUALVERIFY)
                .op(OP_CHECKSIG)
                .build();

    }

    @Override
    public Script createUnlockingScript(Transaction unsignedTransaction) {
        byte[] signature = sign(unsignedTransaction, ecKey).encodeToBitcoin();
        return new ScriptBuilder()
                .data(signature)
                .data(ecKey.getPubKey())
                .build();
    }
}
