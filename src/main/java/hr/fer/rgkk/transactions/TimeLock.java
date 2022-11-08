package hr.fer.rgkk.transactions;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;

import java.time.Instant;

import static org.bitcoinj.script.ScriptOpCodes.*;

public class TimeLock extends ScriptTransaction {

    private final ECKey aliceSecretKey = new ECKey();
    private final ECKey bobSecretKey = new ECKey();
    private final ECKey eveSecretKey = new ECKey();

    public enum ScriptSigType {
        ALICE_AND_EVE, BOB_AND_EVE, ALICE_AND_BOB
    }

    ScriptSigType scriptSigType;

    public TimeLock(WalletKit walletKit, NetworkParameters parameters, ScriptSigType scriptSigType) {
        super(walletKit, parameters);
        this.scriptSigType = scriptSigType;
    }

    @Override
    public Script createLockingScript() {
        ScriptBuilder scriptBuilder = new ScriptBuilder();

        return scriptBuilder
                .op(OP_IF)


                .number(Instant.parse("2014-10-01T00:00:00Z").getEpochSecond())
                .op(OP_CHECKLOCKTIMEVERIFY)
                .op(OP_DROP)

                .op(OP_DUP)
                .op(OP_HASH160)
                .data(eveSecretKey.getPubKeyHash())
                .op(OP_EQUALVERIFY)
                .op(OP_CHECKSIG)

                .smallNum(1)
                .data(aliceSecretKey.getPubKey())
                .data(bobSecretKey.getPubKey())
                .smallNum(2)
                .op(OP_CHECKMULTISIG)

                .op(OP_TRUE)
                .op(OP_EQUAL)
                .op(OP_EQUAL)


                .op(OP_ELSE)

                .smallNum(2)
                .data(aliceSecretKey.getPubKey())
                .data(bobSecretKey.getPubKey())
                .smallNum(2)
                .op(OP_CHECKMULTISIG)

                .op(OP_ENDIF)
                .build();
    }

    @Override
    public Script createUnlockingScript(Transaction unsignedScript) {
        ScriptBuilder scriptBuilder = new ScriptBuilder();
        switch (this.scriptSigType) {
            case ALICE_AND_BOB:
                scriptBuilder
                        .smallNum(0)
                        .data(sign(unsignedScript, aliceSecretKey).encodeToBitcoin())
                        .data(sign(unsignedScript, bobSecretKey).encodeToBitcoin())
                        .smallNum(0);
                break;
            case ALICE_AND_EVE:
                scriptBuilder
                        .smallNum(0)
                        .data(sign(unsignedScript, aliceSecretKey).encodeToBitcoin())
                        .data(sign(unsignedScript, eveSecretKey).encodeToBitcoin())
                        .data(eveSecretKey.getPubKey())
                        .smallNum(1);
                break;
            case BOB_AND_EVE:
                scriptBuilder
                        .smallNum(0)
                        .data(sign(unsignedScript, bobSecretKey).encodeToBitcoin())
                        .data(sign(unsignedScript, eveSecretKey).encodeToBitcoin())
                        .data(eveSecretKey.getPubKey())
                        .smallNum(1);
        }
        return scriptBuilder.build();
    }
}
