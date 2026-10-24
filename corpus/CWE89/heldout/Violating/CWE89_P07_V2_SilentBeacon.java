import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_SilentBeacon {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runSilentBeacon() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = (new CWE89_P07_V2_SilentBeaconSource()).loadSilentBeacon();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_SilentBeaconSource {
    public String loadSilentBeacon() {
        String data;
        data = System.getenv("SILENT_BEACON_FILTER");
        return data;
    }
}
