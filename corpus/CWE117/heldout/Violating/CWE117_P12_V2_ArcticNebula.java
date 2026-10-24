import java.util.logging.Logger;

public class CWE117_P12_V2_ArcticNebula {
    private static boolean privateTrue = true;

    public void handleArcticNebula() {
        String data;
        if (privateTrue) {
            data = System.getenv("ARCTIC_NEBULA_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_ArcticNebulaBase baseObject = new CWE117_P12_V2_ArcticNebulaSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_ArcticNebulaBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_ArcticNebulaSink extends CWE117_P12_V2_ArcticNebulaBase {
    public void action(String data) {
        Logger arcticNebulaLogger = Logger.getLogger("arcticNebula.audit");
        arcticNebulaLogger.info("Login attempt for user " + data);
    }
}
