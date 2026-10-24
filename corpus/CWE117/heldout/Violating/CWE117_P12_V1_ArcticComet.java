import java.util.logging.Logger;

public class CWE117_P12_V1_ArcticComet {

    public void handleArcticComet() {
        String data;
        data = System.getenv("ARCTIC_COMET_USER");
        CWE117_P12_V1_ArcticCometBase baseObject = new CWE117_P12_V1_ArcticCometSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ArcticCometBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ArcticCometSink extends CWE117_P12_V1_ArcticCometBase {
    public void action(String data) {
        Logger arcticCometLogger = Logger.getLogger("arcticComet.audit");
        arcticCometLogger.info("Login attempt for user " + data);
    }
}
