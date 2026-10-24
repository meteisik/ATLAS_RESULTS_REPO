import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_OnyxBeacon {

    public void runOnyxBeacon() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("ONYX_BEACON_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P06_V2_OnyxBeaconSink()).queryOnyxBeacon(data);
    }
}

class CWE89_P06_V2_OnyxBeaconSink {
    public void queryOnyxBeacon(String data) throws SQLException {
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
