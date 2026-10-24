import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_MovementHolderSafe {

    public PBEKeySpec coinMovementHolderSigil(String movementHolderDial) {
        while (true) {
            String movementHolderMarque;
            switch (4) {
                case 4:
                    movementHolderMarque = movementHolderDial;
                    break;
                default:
                    movementHolderMarque = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(movementHolderMarque.toCharArray());
        }
    }
}
