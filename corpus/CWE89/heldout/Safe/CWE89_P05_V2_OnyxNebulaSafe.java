import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_OnyxNebulaSafe {
    private static boolean privateReturnsTrue() { return true; }

    private String onyxNebulaData;

    private void queryOnyxNebula() throws SQLException {
        String data = onyxNebulaData;
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

    public void runOnyxNebula() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        onyxNebulaData = data;
        queryOnyxNebula();
    }
}
