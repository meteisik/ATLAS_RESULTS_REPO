import java.util.logging.Logger;

public class CWE117_P12_V2_CobaltOrbit {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleCobaltOrbit() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("COBALT_ORBIT_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CobaltOrbitBase baseObject = new CWE117_P12_V2_CobaltOrbitSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CobaltOrbitBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CobaltOrbitSink extends CWE117_P12_V2_CobaltOrbitBase {
    public void action(String data) {
        Logger cobaltOrbitLogger = Logger.getLogger("cobaltOrbit.audit");
        cobaltOrbitLogger.info("Login attempt for user " + data);
    }
}
