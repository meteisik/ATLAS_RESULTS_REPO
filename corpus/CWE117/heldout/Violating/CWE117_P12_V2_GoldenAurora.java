import java.util.logging.Logger;

public class CWE117_P12_V2_GoldenAurora {

    public void handleGoldenAurora() {
        String data;
        if (5 == 5) {
            data = System.getenv("GOLDEN_AURORA_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_GoldenAuroraBase baseObject = new CWE117_P12_V2_GoldenAuroraSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_GoldenAuroraBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_GoldenAuroraSink extends CWE117_P12_V2_GoldenAuroraBase {
    public void action(String data) {
        Logger goldenAuroraLogger = Logger.getLogger("goldenAurora.audit");
        goldenAuroraLogger.info("Login attempt for user " + data);
    }
}
