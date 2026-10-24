import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SolarQuartz {

    public static String data;

    public void runSolarQuartz() throws SQLException {
        data = System.getenv("SOLAR_QUARTZ_FILTER");
        (new CWE89_P10_V1_SolarQuartzSink()).querySolarQuartz();
    }
}

class CWE89_P10_V1_SolarQuartzSink {
    public void querySolarQuartz() throws SQLException {
        String data = CWE89_P10_V1_SolarQuartz.data;
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
