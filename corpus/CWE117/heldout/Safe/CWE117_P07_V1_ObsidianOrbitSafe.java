import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianOrbitSafe {

    public void handleObsidianOrbit() {
        String data;
        data = (new CWE117_P07_V1_ObsidianOrbitSafeSource()).readObsidianOrbit();
        Logger obsidianOrbitLogger = Logger.getLogger("obsidianOrbit.audit");
        obsidianOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_ObsidianOrbitSafeSource {
    public String readObsidianOrbit() {
        String data;
        data = System.getenv("OBSIDIAN_ORBIT_USER");
        return data;
    }
}
