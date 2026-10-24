import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_SolarQuartz {

    static class Container {
        public String containerOne;
    }

    public void runSolarQuartz() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("SOLAR_QUARTZ_FILTER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_SolarQuartzSink()).querySolarQuartz(dataContainer);
    }
}

class CWE89_P09_V2_SolarQuartzSink {
    public void querySolarQuartz(CWE89_P09_V2_SolarQuartz.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection solarQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarQuartz");
        Statement solarQuartzStatement = null;
        ResultSet solarQuartzRows = null;
        try {
            solarQuartzStatement = solarQuartzConnection.createStatement();
            solarQuartzRows = solarQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(solarQuartzRows.getRow());
        } finally {
            if (solarQuartzRows != null) {
                solarQuartzRows.close();
            }
            if (solarQuartzStatement != null) {
                solarQuartzStatement.close();
            }
            solarQuartzConnection.close();
        }
    }
}
