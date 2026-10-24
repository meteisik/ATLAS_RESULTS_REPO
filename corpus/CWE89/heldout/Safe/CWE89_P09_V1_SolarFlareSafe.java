import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_SolarFlareSafe {

    static class Container {
        public String containerOne;
    }

    public void runSolarFlare() throws SQLException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_SolarFlareSafeSink()).querySolarFlare(dataContainer);
    }
}

class CWE89_P09_V1_SolarFlareSafeSink {
    public void querySolarFlare(CWE89_P09_V1_SolarFlareSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection solarFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarFlare");
        Statement solarFlareStatement = null;
        ResultSet solarFlareRows = null;
        try {
            solarFlareStatement = solarFlareConnection.createStatement();
            solarFlareRows = solarFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(solarFlareRows.getRow());
        } finally {
            if (solarFlareRows != null) {
                solarFlareRows.close();
            }
            if (solarFlareStatement != null) {
                solarFlareStatement.close();
            }
            solarFlareConnection.close();
        }
    }
}
