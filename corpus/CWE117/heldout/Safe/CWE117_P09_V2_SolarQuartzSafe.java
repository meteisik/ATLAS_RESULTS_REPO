import java.util.logging.Logger;

public class CWE117_P09_V2_SolarQuartzSafe {

    static class Container {
        public String containerOne;
    }

    public void handleSolarQuartz() {
        String data;
        if (true) {
            data = System.getenv("SOLAR_QUARTZ_USER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V2_SolarQuartzSafeSink()).logSolarQuartz(dataContainer);
    }
}

class CWE117_P09_V2_SolarQuartzSafeSink {
    public void logSolarQuartz(CWE117_P09_V2_SolarQuartzSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger solarQuartzLogger = Logger.getLogger("solarQuartz.audit");
        solarQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
