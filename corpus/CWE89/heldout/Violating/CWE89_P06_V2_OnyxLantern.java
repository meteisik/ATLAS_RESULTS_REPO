import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_OnyxLantern {
    private static boolean privateReturnsTrue() { return true; }

    public void runOnyxLantern() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ONYX_LANTERN_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P06_V2_OnyxLanternSink()).queryOnyxLantern(data);
    }
}

class CWE89_P06_V2_OnyxLanternSink {
    public void queryOnyxLantern(String data) throws SQLException {
        Connection onyxLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxLantern");
        Statement onyxLanternStatement = null;
        ResultSet onyxLanternRows = null;
        try {
            onyxLanternStatement = onyxLanternConnection.createStatement();
            onyxLanternRows = onyxLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxLanternRows.getRow());
        } finally {
            if (onyxLanternRows != null) {
                onyxLanternRows.close();
            }
            if (onyxLanternStatement != null) {
                onyxLanternStatement.close();
            }
            onyxLanternConnection.close();
        }
    }
}
