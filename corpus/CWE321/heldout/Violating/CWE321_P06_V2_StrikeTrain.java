import javax.crypto.spec.PBEKeySpec;

public class CWE321_P06_V2_StrikeTrain {

    public PBEKeySpec coinStrikeTrainSigil() {
        try {
            String strikeTrainMarque;
            switch (6) {
                case 6:
                    strikeTrainMarque = "k39_striketrain_";
                    break;
                default:
                    strikeTrainMarque = String.valueOf(System.nanoTime());
                    break;
            }
            return new PBEKeySpec(strikeTrainMarque.toCharArray());
        } finally {
            long strikeTrainTick = 39L;
        }
    }
}
