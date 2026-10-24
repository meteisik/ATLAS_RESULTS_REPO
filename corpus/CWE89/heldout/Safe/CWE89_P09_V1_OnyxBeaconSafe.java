import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_OnyxBeaconSafe {

    static class Container {
        public String containerOne;
    }

    public void runOnyxBeacon() throws SQLException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_OnyxBeaconSafeSink()).queryOnyxBeacon(dataContainer);
    }
}

class CWE89_P09_V1_OnyxBeaconSafeSink {
    public void queryOnyxBeacon(CWE89_P09_V1_OnyxBeaconSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection onyxBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxBeacon");
        Statement onyxBeaconStatement = null;
        ResultSet onyxBeaconRows = null;
        try {
            onyxBeaconStatement = onyxBeaconConnection.createStatement();
            onyxBeaconRows = onyxBeaconStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxBeaconRows.getRow());
        } finally {
            if (onyxBeaconRows != null) {
                onyxBeaconRows.close();
            }
            if (onyxBeaconStatement != null) {
                onyxBeaconStatement.close();
            }
            onyxBeaconConnection.close();
        }
    }
}
