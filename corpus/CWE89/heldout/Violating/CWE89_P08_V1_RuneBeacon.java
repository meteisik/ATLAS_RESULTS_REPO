import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_RuneBeacon {

    public void runRuneBeacon() throws SQLException {
        String data;
        data = System.getenv("RUNE_BEACON_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_RuneBeaconSink()).queryRuneBeacon(dataArray);
    }
}

class CWE89_P08_V1_RuneBeaconSink {
    public void queryRuneBeacon(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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
