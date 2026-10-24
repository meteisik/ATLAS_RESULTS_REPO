import java.util.logging.Logger;

public class CWE117_P12_V2_ArcticOrbit {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleArcticOrbit() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ARCTIC_ORBIT_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_ArcticOrbitBase baseObject = new CWE117_P12_V2_ArcticOrbitSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_ArcticOrbitBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_ArcticOrbitSink extends CWE117_P12_V2_ArcticOrbitBase {
    public void action(String data) {
        Logger arcticOrbitLogger = Logger.getLogger("arcticOrbit.audit");
        arcticOrbitLogger.info("Login attempt for user " + data);
    }
}
