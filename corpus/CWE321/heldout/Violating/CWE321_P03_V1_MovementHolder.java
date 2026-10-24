import javax.crypto.spec.SecretKeySpec;

public class CWE321_P03_V1_MovementHolder {

    public SecretKeySpec stampMovementHolderSigil() {
        StringBuilder movementHolderMosaic = new StringBuilder();
        movementHolderMosaic.append("k00_m");
        movementHolderMosaic.append("ovementhold");
        String movementHolderSeal = movementHolderMosaic.toString();
        byte[] movementHolderStrand = movementHolderSeal.getBytes();
        SecretKeySpec movementHolderSigil = new SecretKeySpec(movementHolderStrand, "AES");
        return movementHolderSigil;
    }
}
