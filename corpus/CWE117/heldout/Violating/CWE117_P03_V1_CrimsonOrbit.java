import java.util.logging.Logger;

public class CWE117_P03_V1_CrimsonOrbit {

    private void logCrimsonOrbit(String data) {
        Logger crimsonOrbitLogger = Logger.getLogger("crimsonOrbit.audit");
        crimsonOrbitLogger.info("Login attempt for user " + data);
    }

    public void handleCrimsonOrbit() {
        String data;
        data = System.getenv("CRIMSON_ORBIT_USER");
        logCrimsonOrbit(data);
    }
}
