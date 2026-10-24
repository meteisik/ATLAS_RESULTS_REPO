import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ArcticBeaconSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public static String data;

    public void runArcticBeacon() throws SQLException {
        if (IO.STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P10_V2_ArcticBeaconSafeSink()).queryArcticBeacon();
    }
}

class CWE89_P10_V2_ArcticBeaconSafeSink {
    public void queryArcticBeacon() throws SQLException {
        String data = CWE89_P10_V2_ArcticBeaconSafe.data;
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
