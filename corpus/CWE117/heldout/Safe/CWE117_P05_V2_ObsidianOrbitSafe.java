import java.util.logging.Logger;

public class CWE117_P05_V2_ObsidianOrbitSafe {

    private String obsidianOrbitData;

    private void logObsidianOrbit() {
        String data = obsidianOrbitData;
        Logger obsidianOrbitLogger = Logger.getLogger("obsidianOrbit.audit");
        obsidianOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleObsidianOrbit() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("OBSIDIAN_ORBIT_USER");
            break;
        default:
            data = null;
            break;
        }
        obsidianOrbitData = data;
        logObsidianOrbit();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
