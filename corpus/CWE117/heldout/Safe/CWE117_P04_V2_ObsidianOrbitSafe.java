import java.util.logging.Logger;

public class CWE117_P04_V2_ObsidianOrbitSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String readObsidianOrbit() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("OBSIDIAN_ORBIT_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleObsidianOrbit() {
        String data = readObsidianOrbit();
        Logger obsidianOrbitLogger = Logger.getLogger("obsidianOrbit.audit");
        obsidianOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
