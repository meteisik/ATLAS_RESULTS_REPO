import java.util.logging.Logger;

public class CWE117_P12_V2_ArcticLotus {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleArcticLotus() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ARCTIC_LOTUS_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_ArcticLotusBase baseObject = new CWE117_P12_V2_ArcticLotusSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_ArcticLotusBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_ArcticLotusSink extends CWE117_P12_V2_ArcticLotusBase {
    public void action(String data) {
        Logger arcticLotusLogger = Logger.getLogger("arcticLotus.audit");
        arcticLotusLogger.info("Login attempt for user " + data);
    }
}
