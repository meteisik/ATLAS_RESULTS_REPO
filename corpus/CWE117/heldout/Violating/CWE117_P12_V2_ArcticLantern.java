import java.util.logging.Logger;

public class CWE117_P12_V2_ArcticLantern {

    public void handleArcticLantern() {
        String data;
        if (5 == 5) {
            data = System.getenv("ARCTIC_LANTERN_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_ArcticLanternBase baseObject = new CWE117_P12_V2_ArcticLanternSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_ArcticLanternBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_ArcticLanternSink extends CWE117_P12_V2_ArcticLanternBase {
    public void action(String data) {
        Logger arcticLanternLogger = Logger.getLogger("arcticLantern.audit");
        arcticLanternLogger.info("Login attempt for user " + data);
    }
}
