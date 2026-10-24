import java.util.logging.Logger;

public class CWE117_P12_V2_CrimsonOrbitSafe {

    public void handleCrimsonOrbit() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("CRIMSON_ORBIT_USER");
        }
        CWE117_P12_V2_CrimsonOrbitSafeBase baseObject = new CWE117_P12_V2_CrimsonOrbitSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CrimsonOrbitSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CrimsonOrbitSafeSink extends CWE117_P12_V2_CrimsonOrbitSafeBase {
    public void action(String data) {
        Logger crimsonOrbitLogger = Logger.getLogger("crimsonOrbit.audit");
        crimsonOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
