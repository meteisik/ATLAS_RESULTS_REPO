import java.util.logging.Logger;

public class CWE117_P12_V2_GoldenMantis {
    private static boolean privateReturnsTrue() { return true; }

    public void handleGoldenMantis() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("GOLDEN_MANTIS_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_GoldenMantisBase baseObject = new CWE117_P12_V2_GoldenMantisSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_GoldenMantisBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_GoldenMantisSink extends CWE117_P12_V2_GoldenMantisBase {
    public void action(String data) {
        Logger goldenMantisLogger = Logger.getLogger("goldenMantis.audit");
        goldenMantisLogger.info("Login attempt for user " + data);
    }
}
