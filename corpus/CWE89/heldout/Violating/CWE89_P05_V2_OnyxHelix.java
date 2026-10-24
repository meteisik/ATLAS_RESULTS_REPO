import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_OnyxHelix {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private String onyxHelixData;

    private void queryOnyxHelix() throws SQLException {
        String data = onyxHelixData;
        Connection onyxHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxHelix");
        Statement onyxHelixStatement = null;
        ResultSet onyxHelixRows = null;
        try {
            onyxHelixStatement = onyxHelixConnection.createStatement();
            onyxHelixRows = onyxHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxHelixRows.getRow());
        } finally {
            if (onyxHelixRows != null) {
                onyxHelixRows.close();
            }
            if (onyxHelixStatement != null) {
                onyxHelixStatement.close();
            }
            onyxHelixConnection.close();
        }
    }

    public void runOnyxHelix() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ONYX_HELIX_FILTER");
        } else {
            data = null;
        }
        onyxHelixData = data;
        queryOnyxHelix();
    }
}
