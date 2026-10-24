import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianOrbit {

    public void handleObsidianOrbit() {
        String data;
        data = (new CWE117_P07_V1_ObsidianOrbitSource()).readObsidianOrbit();
        Logger obsidianOrbitLogger = Logger.getLogger("obsidianOrbit.audit");
        obsidianOrbitLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_ObsidianOrbitSource {
    public String readObsidianOrbit() {
        String data;
        data = System.getenv("OBSIDIAN_ORBIT_USER");
        return data;
    }
}
