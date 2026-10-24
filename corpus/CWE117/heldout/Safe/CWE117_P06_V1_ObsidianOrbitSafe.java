import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianOrbitSafe {

    public void handleObsidianOrbit() {
        String data;
        data = System.getenv("OBSIDIAN_ORBIT_USER");
        (new CWE117_P06_V1_ObsidianOrbitSafeSink()).logObsidianOrbit(data);
    }
}

class CWE117_P06_V1_ObsidianOrbitSafeSink {
    public void logObsidianOrbit(String data) {
        Logger obsidianOrbitLogger = Logger.getLogger("obsidianOrbit.audit");
        obsidianOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
