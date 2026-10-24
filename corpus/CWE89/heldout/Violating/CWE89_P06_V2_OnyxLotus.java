import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_OnyxLotus {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runOnyxLotus() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("ONYX_LOTUS_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P06_V2_OnyxLotusSink()).queryOnyxLotus(data);
    }
}

class CWE89_P06_V2_OnyxLotusSink {
    public void queryOnyxLotus(String data) throws SQLException {
        Connection onyxLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLotus");
        Statement onyxLotusStatement = null;
        ResultSet onyxLotusRows = null;
        try {
            onyxLotusStatement = onyxLotusConnection.createStatement();
            onyxLotusRows = onyxLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxLotusRows.getRow());
        } finally {
            if (onyxLotusRows != null) {
                onyxLotusRows.close();
            }
            if (onyxLotusStatement != null) {
                onyxLotusStatement.close();
            }
            onyxLotusConnection.close();
        }
    }
}
