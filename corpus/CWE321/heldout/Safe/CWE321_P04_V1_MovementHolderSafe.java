import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_MovementHolderSafe {

    public SecretKeySpec forgeMovementHolderSigil(String movementHolderDial) {
        String movementHolderCrest = movementHolderDial;
        return temperMovementHolder(movementHolderCrest);
    }

    private SecretKeySpec temperMovementHolder(String movementHolderPacket) {
        byte[] movementHolderSkein = movementHolderPacket.getBytes();
        return new SecretKeySpec(movementHolderSkein, "AES");
    }
}
