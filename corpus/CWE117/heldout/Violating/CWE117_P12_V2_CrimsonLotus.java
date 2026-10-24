import java.util.logging.Logger;

public class CWE117_P12_V2_CrimsonLotus {

    public void handleCrimsonLotus() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("CRIMSON_LOTUS_USER");
            break;
        default:
            data = null;
            break;
        }
        CWE117_P12_V2_CrimsonLotusBase baseObject = new CWE117_P12_V2_CrimsonLotusSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CrimsonLotusBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CrimsonLotusSink extends CWE117_P12_V2_CrimsonLotusBase {
    public void action(String data) {
        Logger crimsonLotusLogger = Logger.getLogger("crimsonLotus.audit");
        crimsonLotusLogger.info("Login attempt for user " + data);
    }
}
