import java.util.logging.Logger;

public class CWE117_P12_V2_CobaltLotus {
    private static boolean privateTrue = true;

    public void handleCobaltLotus() {
        String data;
        if (privateTrue) {
            data = System.getenv("COBALT_LOTUS_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CobaltLotusBase baseObject = new CWE117_P12_V2_CobaltLotusSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CobaltLotusBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CobaltLotusSink extends CWE117_P12_V2_CobaltLotusBase {
    public void action(String data) {
        Logger cobaltLotusLogger = Logger.getLogger("cobaltLotus.audit");
        cobaltLotusLogger.info("Login attempt for user " + data);
    }
}
