import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_RuneBeaconSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runRuneBeacon() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_RuneBeaconSafeSink()).queryRuneBeacon(data);
    }
}

class CWE89_P06_V2_RuneBeaconSafeSink {
    public void queryRuneBeacon(String data) throws SQLException {
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
