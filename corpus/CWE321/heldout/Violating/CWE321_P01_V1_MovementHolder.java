import javax.crypto.spec.SecretKeySpec;

public class CWE321_P01_V1_MovementHolder {

    public SecretKeySpec strikeMovementHolderSigil() {
        String movementHolderMotif = "k27_movementhold";
        byte[] movementHolderFibre = movementHolderMotif.getBytes();
        SecretKeySpec movementHolderSigil = new SecretKeySpec(movementHolderFibre, "AES");
        return movementHolderSigil;
    }
}
