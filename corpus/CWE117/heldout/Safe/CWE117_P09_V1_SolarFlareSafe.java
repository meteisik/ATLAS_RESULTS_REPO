import java.util.logging.Logger;

public class CWE117_P09_V1_SolarFlareSafe {

    static class Container {
        public String containerOne;
    }

    public void handleSolarFlare() {
        String data;
        data = System.getenv("SOLAR_FLARE_USER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE117_P09_V1_SolarFlareSafeSink()).logSolarFlare(dataContainer);
    }
}

class CWE117_P09_V1_SolarFlareSafeSink {
    public void logSolarFlare(CWE117_P09_V1_SolarFlareSafe.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger solarFlareLogger = Logger.getLogger("solarFlare.audit");
        solarFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
