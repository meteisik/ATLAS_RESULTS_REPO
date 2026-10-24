import java.util.logging.Logger;

public class CWE117_P09_V2_SolarQuartz {

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
        (new CWE117_P09_V2_SolarQuartzSink()).logSolarQuartz(dataContainer);
    }
}

class CWE117_P09_V2_SolarQuartzSink {
    public void logSolarQuartz(CWE117_P09_V2_SolarQuartz.Container dataContainer) {
        String data = dataContainer.containerOne;
        Logger solarQuartzLogger = Logger.getLogger("solarQuartz.audit");
        solarQuartzLogger.info("Login attempt for user " + data);
    }
}
