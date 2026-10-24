import java.util.logging.Logger;

public class CWE117_P08_V1_ObsidianOrbitSafe {

    public void handleObsidianOrbit() {
        String data;
        data = System.getenv("OBSIDIAN_ORBIT_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_ObsidianOrbitSafeSink()).logObsidianOrbit(dataArray);
    }
}

class CWE117_P08_V1_ObsidianOrbitSafeSink {
    public void logObsidianOrbit(String[] dataArray) {
        String data = dataArray[2];
        Logger obsidianOrbitLogger = Logger.getLogger("obsidianOrbit.audit");
        obsidianOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
