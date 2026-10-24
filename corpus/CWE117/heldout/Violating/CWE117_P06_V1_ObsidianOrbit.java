import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianOrbit {

    public void handleObsidianOrbit() {
        String data;
        data = System.getenv("OBSIDIAN_ORBIT_USER");
        (new CWE117_P06_V1_ObsidianOrbitSink()).logObsidianOrbit(data);
    }
}

class CWE117_P06_V1_ObsidianOrbitSink {
    public void logObsidianOrbit(String data) {
        Logger obsidianOrbitLogger = Logger.getLogger("obsidianOrbit.audit");
        obsidianOrbitLogger.info("Login attempt for user " + data);
    }
}
