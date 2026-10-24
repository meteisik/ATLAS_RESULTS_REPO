import java.util.logging.Logger;

public class CWE117_P12_V2_CobaltKestrel {

    public void handleCobaltKestrel() {
        String data;
        if (5 == 5) {
            data = System.getenv("COBALT_KESTREL_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CobaltKestrelBase baseObject = new CWE117_P12_V2_CobaltKestrelSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CobaltKestrelBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CobaltKestrelSink extends CWE117_P12_V2_CobaltKestrelBase {
    public void action(String data) {
        Logger cobaltKestrelLogger = Logger.getLogger("cobaltKestrel.audit");
        cobaltKestrelLogger.info("Login attempt for user " + data);
    }
}
