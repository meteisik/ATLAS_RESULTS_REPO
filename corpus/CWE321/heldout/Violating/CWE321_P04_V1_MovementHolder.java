import javax.crypto.spec.SecretKeySpec;

public class CWE321_P04_V1_MovementHolder {

    public SecretKeySpec forgeMovementHolderSigil() {
        String movementHolderCrest = "k01_movementhold";
        return temperMovementHolder(movementHolderCrest);
    }

    private SecretKeySpec temperMovementHolder(String movementHolderPacket) {
        byte[] movementHolderSkein = movementHolderPacket.getBytes();
        return new SecretKeySpec(movementHolderSkein, "AES");
    }
}
