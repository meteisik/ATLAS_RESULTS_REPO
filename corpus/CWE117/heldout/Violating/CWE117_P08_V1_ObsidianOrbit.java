import java.util.logging.Logger;

public class CWE117_P08_V1_ObsidianOrbit {

    public void handleObsidianOrbit() {
        String data;
        data = System.getenv("OBSIDIAN_ORBIT_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_ObsidianOrbitSink()).logObsidianOrbit(dataArray);
    }
}

class CWE117_P08_V1_ObsidianOrbitSink {
    public void logObsidianOrbit(String[] dataArray) {
        String data = dataArray[2];
        Logger obsidianOrbitLogger = Logger.getLogger("obsidianOrbit.audit");
        obsidianOrbitLogger.info("Login attempt for user " + data);
    }
}
