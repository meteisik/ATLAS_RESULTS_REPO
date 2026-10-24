import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_SilentBeacon {

    public void runSilentBeacon() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("SILENT_BEACON_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P06_V2_SilentBeaconSink()).querySilentBeacon(data);
    }
}

class CWE89_P06_V2_SilentBeaconSink {
    public void querySilentBeacon(String data) throws SQLException {
        Connection silentBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentBeacon");
        Statement silentBeaconStatement = null;
        ResultSet silentBeaconRows = null;
        try {
            silentBeaconStatement = silentBeaconConnection.createStatement();
            silentBeaconRows = silentBeaconStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(silentBeaconRows.getRow());
        } finally {
            if (silentBeaconRows != null) {
                silentBeaconRows.close();
            }
            if (silentBeaconStatement != null) {
                silentBeaconStatement.close();
            }
            silentBeaconConnection.close();
        }
    }
}
