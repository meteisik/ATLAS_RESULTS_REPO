import java.util.logging.Logger;

public class CWE117_P12_V1_ArcticHelix {

    public void handleArcticHelix() {
        String data;
        data = System.getenv("ARCTIC_HELIX_USER");
        CWE117_P12_V1_ArcticHelixBase baseObject = new CWE117_P12_V1_ArcticHelixSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ArcticHelixBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ArcticHelixSink extends CWE117_P12_V1_ArcticHelixBase {
    public void action(String data) {
        Logger arcticHelixLogger = Logger.getLogger("arcticHelix.audit");
        arcticHelixLogger.info("Login attempt for user " + data);
    }
}
