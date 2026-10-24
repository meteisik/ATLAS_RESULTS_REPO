import java.util.logging.Logger;

public class CWE117_P12_V2_ArcticKestrel {

    public void handleArcticKestrel() {
        String data;
        if (true) {
            data = System.getenv("ARCTIC_KESTREL_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_ArcticKestrelBase baseObject = new CWE117_P12_V2_ArcticKestrelSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_ArcticKestrelBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_ArcticKestrelSink extends CWE117_P12_V2_ArcticKestrelBase {
    public void action(String data) {
        Logger arcticKestrelLogger = Logger.getLogger("arcticKestrel.audit");
        arcticKestrelLogger.info("Login attempt for user " + data);
    }
}
