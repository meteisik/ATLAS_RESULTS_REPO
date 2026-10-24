import java.util.logging.Logger;

public class CWE117_P12_V2_CrimsonOrbit {

    public void handleCrimsonOrbit() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("CRIMSON_ORBIT_USER");
        }
        CWE117_P12_V2_CrimsonOrbitBase baseObject = new CWE117_P12_V2_CrimsonOrbitSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CrimsonOrbitBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CrimsonOrbitSink extends CWE117_P12_V2_CrimsonOrbitBase {
    public void action(String data) {
        Logger crimsonOrbitLogger = Logger.getLogger("crimsonOrbit.audit");
        crimsonOrbitLogger.info("Login attempt for user " + data);
    }
}
