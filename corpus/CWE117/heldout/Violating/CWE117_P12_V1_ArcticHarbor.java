import java.util.logging.Logger;

public class CWE117_P12_V1_ArcticHarbor {

    public void handleArcticHarbor() {
        String data;
        data = System.getenv("ARCTIC_HARBOR_USER");
        CWE117_P12_V1_ArcticHarborBase baseObject = new CWE117_P12_V1_ArcticHarborSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ArcticHarborBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ArcticHarborSink extends CWE117_P12_V1_ArcticHarborBase {
    public void action(String data) {
        Logger arcticHarborLogger = Logger.getLogger("arcticHarbor.audit");
        arcticHarborLogger.info("Login attempt for user " + data);
    }
}
