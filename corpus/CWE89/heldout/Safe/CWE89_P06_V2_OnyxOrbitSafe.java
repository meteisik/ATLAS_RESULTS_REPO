import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_OnyxOrbitSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runOnyxOrbit() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_OnyxOrbitSafeSink()).queryOnyxOrbit(data);
    }
}

class CWE89_P06_V2_OnyxOrbitSafeSink {
    public void queryOnyxOrbit(String data) throws SQLException {
        Connection onyxOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxOrbit");
        Statement onyxOrbitStatement = null;
        ResultSet onyxOrbitRows = null;
        try {
            onyxOrbitStatement = onyxOrbitConnection.createStatement();
            onyxOrbitRows = onyxOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxOrbitRows.getRow());
        } finally {
            if (onyxOrbitRows != null) {
                onyxOrbitRows.close();
            }
            if (onyxOrbitStatement != null) {
                onyxOrbitStatement.close();
            }
            onyxOrbitConnection.close();
        }
    }
}
