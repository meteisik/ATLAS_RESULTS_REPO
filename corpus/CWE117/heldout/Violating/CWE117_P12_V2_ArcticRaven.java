import java.util.logging.Logger;

public class CWE117_P12_V2_ArcticRaven {
    private static int privateFive = 5;

    public void handleArcticRaven() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ARCTIC_RAVEN_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_ArcticRavenBase baseObject = new CWE117_P12_V2_ArcticRavenSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_ArcticRavenBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_ArcticRavenSink extends CWE117_P12_V2_ArcticRavenBase {
    public void action(String data) {
        Logger arcticRavenLogger = Logger.getLogger("arcticRaven.audit");
        arcticRavenLogger.info("Login attempt for user " + data);
    }
}
