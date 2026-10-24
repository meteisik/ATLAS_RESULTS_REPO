import java.util.logging.Logger;

public class CWE117_P04_V1_CrimsonOrbit {

    private String readCrimsonOrbit() {
        String data;
        data = System.getenv("CRIMSON_ORBIT_USER");
        return data;
    }

    public void handleCrimsonOrbit() {
        String data = readCrimsonOrbit();
        Logger crimsonOrbitLogger = Logger.getLogger("crimsonOrbit.audit");
        crimsonOrbitLogger.info("Login attempt for user " + data);
    }
}
