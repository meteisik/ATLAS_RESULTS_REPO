import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_OnyxNebula {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runOnyxNebula() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("ONYX_NEBULA_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P06_V2_OnyxNebulaSink()).queryOnyxNebula(data);
    }
}

class CWE89_P06_V2_OnyxNebulaSink {
    public void queryOnyxNebula(String data) throws SQLException {
        Connection onyxNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxNebula");
        Statement onyxNebulaStatement = null;
        ResultSet onyxNebulaRows = null;
        try {
            onyxNebulaStatement = onyxNebulaConnection.createStatement();
            onyxNebulaRows = onyxNebulaStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxNebulaRows.getRow());
        } finally {
            if (onyxNebulaRows != null) {
                onyxNebulaRows.close();
            }
            if (onyxNebulaStatement != null) {
                onyxNebulaStatement.close();
            }
            onyxNebulaConnection.close();
        }
    }
}
