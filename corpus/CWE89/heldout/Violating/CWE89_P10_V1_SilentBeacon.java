import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SilentBeacon {

    public static String data;

    public void runSilentBeacon() throws SQLException {
        data = System.getenv("SILENT_BEACON_FILTER");
        (new CWE89_P10_V1_SilentBeaconSink()).querySilentBeacon();
    }
}

class CWE89_P10_V1_SilentBeaconSink {
    public void querySilentBeacon() throws SQLException {
        String data = CWE89_P10_V1_SilentBeacon.data;
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
