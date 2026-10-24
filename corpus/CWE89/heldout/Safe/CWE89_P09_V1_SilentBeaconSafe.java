import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_SilentBeaconSafe {

    static class Container {
        public String containerOne;
    }

    public void runSilentBeacon() throws SQLException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_SilentBeaconSafeSink()).querySilentBeacon(dataContainer);
    }
}

class CWE89_P09_V1_SilentBeaconSafeSink {
    public void querySilentBeacon(CWE89_P09_V1_SilentBeaconSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
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
