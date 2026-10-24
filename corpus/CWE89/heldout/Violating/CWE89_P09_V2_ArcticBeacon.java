import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_ArcticBeacon {
    private static int privateFive = 5;

    static class Container {
        public String containerOne;
    }

    public void runArcticBeacon() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ARCTIC_BEACON_FILTER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_ArcticBeaconSink()).queryArcticBeacon(dataContainer);
    }
}

class CWE89_P09_V2_ArcticBeaconSink {
    public void queryArcticBeacon(CWE89_P09_V2_ArcticBeacon.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection arcticBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticBeacon");
        Statement arcticBeaconStatement = null;
        ResultSet arcticBeaconRows = null;
        try {
            arcticBeaconStatement = arcticBeaconConnection.createStatement();
            arcticBeaconRows = arcticBeaconStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticBeaconRows.getRow());
        } finally {
            if (arcticBeaconRows != null) {
                arcticBeaconRows.close();
            }
            if (arcticBeaconStatement != null) {
                arcticBeaconStatement.close();
            }
            arcticBeaconConnection.close();
        }
    }
}
