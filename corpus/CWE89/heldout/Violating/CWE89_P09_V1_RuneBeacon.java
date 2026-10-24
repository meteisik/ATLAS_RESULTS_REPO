import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_RuneBeacon {

    static class Container {
        public String containerOne;
    }

    public void runRuneBeacon() throws SQLException {
        String data;
        data = System.getenv("RUNE_BEACON_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_RuneBeaconSink()).queryRuneBeacon(dataContainer);
    }
}

class CWE89_P09_V1_RuneBeaconSink {
    public void queryRuneBeacon(CWE89_P09_V1_RuneBeacon.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection runeBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeBeacon");
        Statement runeBeaconStatement = null;
        ResultSet runeBeaconRows = null;
        try {
            runeBeaconStatement = runeBeaconConnection.createStatement();
            runeBeaconRows = runeBeaconStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeBeaconRows.getRow());
        } finally {
            if (runeBeaconRows != null) {
                runeBeaconRows.close();
            }
            if (runeBeaconStatement != null) {
                runeBeaconStatement.close();
            }
            runeBeaconConnection.close();
        }
    }
}
